package manifest

import (
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/Sirupsen/logrus"
	"golang.org/x/net/context"

	"github.com/docker/distribution/registry/api/errcode"
	"github.com/docker/distribution/registry/client"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/cli"
	"github.com/docker/docker/cli/command"
	"github.com/docker/docker/distribution"
	"github.com/docker/docker/dockerversion"
	"github.com/docker/docker/image"
	"github.com/docker/docker/reference"
	"github.com/docker/docker/registry"
	"github.com/spf13/cobra"
	//	"github.com/spf13/pflag"
)

type fetchOptions struct {
	remote string
}

type manifestFetcher interface {
	Fetch(ctx context.Context, ref reference.Named) ([]ImgManifestInspect, error)
}

// NewListFetchCommand creates a new `docker manifest fetch` command
func newListFetchCommand(dockerCli *command.DockerCli) *cobra.Command {
	var opts fetchOptions

	cmd := &cobra.Command{
		Use:   "fetch [OPTIONS] NAME[:TAG]",
		Short: "Fetch an image's manifest list from a registry",
		Args:  cli.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.remote = args[0]

			return runListFetch(dockerCli, opts)
		},
	}

	return cmd
}

func runListFetch(dockerCli *command.DockerCli, opts fetchOptions) error {
	// Get the data and then format it
	name := opts.remote
	_, _, err := getImageData(dockerCli, name, true)
	if err != nil {
		logrus.Fatal(err)
	}

	return nil
}

func storeManifest(imgInspect *[]ImgManifestInspect, overwrite bool) error {
	// Store this image so that it can be annotated.

	var (
		curUser *user.User
		err     error
		newDir  string
		fd      *os.File
	)

	// This seems overkill, but for now, to avoid a panic on a staticly-linked binary, lock this goroutine to its current thread.
	// See https://github.com/golang/go/issues/13470#issuecomment-162622286
	// estesp worked around this for userns uid lookups but that is if you have an id already:
	// https://github.com/docker/docker/issues/20191#issuecomment-255209782
	// But we might not even store these this way, so, figure it out in design review.
	runtime.LockOSThread()
	if curUser, err = user.Current(); err != nil {
		fmt.Errorf("Error retreiving user: %s", err)
		return err
	}
	runtime.UnlockOSThread()

	// @TODO: Will this always exist?
	newDir = fmt.Sprintf("%s/.docker/manifests/", curUser.HomeDir)
	os.MkdirAll(newDir, 0755)
	for i, mf := range *imgInspect {
		fd, err = getManifestFd(mf.Digest)
		defer fd.Close()
		if err != nil {
			fmt.Printf("Store manifests: getManifestFd err: %s\n", err)
			return err
		}
		if fd != nil && overwrite == false {
			logrus.Debug("Not overwriting existing manifest file")
			localMfstInspect, err := unmarshalIntoManifestInspect(fd)
			if err != nil {
				fmt.Printf("Store: Marshal error for %s: %e\n", mf.Tag, err)
				return err
			}
			(*imgInspect)[i] = localMfstInspect
			continue
		} else {
			if err = updateMfFile(mf); err != nil {
				// update overwrites, so can be used to make a new copy
				fmt.Printf("Error writing new local manifest copy: %s\n", err)
				return err
			}
		}
	}

	return nil
}

func getImageData(dockerCli *command.DockerCli, name string, overwrite bool) ([]ImgManifestInspect, *registry.RepositoryInfo, error) {
	// Pull from repo.

	if _, _, err := reference.ParseIDOrReference(name); err != nil {
		return nil, nil, fmt.Errorf("Error parsing reference: %s\n", err)
	}

	namedRef, err := reference.ParseNamed(name)
	// Resolve the Repository name from fqn to RepositoryInfo
	repoInfo, err := registry.ParseRepositoryInfo(namedRef)
	if err != nil {
		return nil, nil, err
	}

	ctx := context.Background()

	authConfig := command.ResolveAuthConfig(ctx, dockerCli, repoInfo.Index)

	options := registry.ServiceOptions{}
	options.InsecureRegistries = append(options.InsecureRegistries, "0.0.0.0/0")
	registryService := registry.NewService(options)

	// a list of registry.APIEndpoint, which could be mirrors, etc., of locally-configured
	// repo endpoints. The list will be ordered by priority (v2, https, v1).
	endpoints, err := registryService.LookupPullEndpoints(repoInfo.Hostname())
	if err != nil {
		return nil, nil, err
	}
	logrus.Debugf("manifest pull: endpoints: %v", endpoints)

	var (
		lastErr                error
		discardNoSupportErrors bool
		foundImages            []ImgManifestInspect
		confirmedV2            bool
		confirmedTLSRegistries = make(map[string]struct{})
	)

	// Try to find the first endpoint that is *both* v2 and using TLS.
	for _, endpoint := range endpoints {
		// make sure I can reach the registry, same as docker pull does
		v1endpoint, err := endpoint.ToV1Endpoint(dockerversion.DockerUserAgent(nil), nil)
		if err != nil {
			return nil, nil, err
		}
		if _, err := v1endpoint.Ping(); err != nil {
			if strings.Contains(err.Error(), "timeout") {
				return nil, nil, err
			}
			continue
		}

		if confirmedV2 && endpoint.Version == registry.APIVersion1 {
			logrus.Debugf("Skipping v1 endpoint %s because v2 registry was detected", endpoint.URL)
			continue
		}

		if endpoint.URL.Scheme != "https" {
			if _, confirmedTLS := confirmedTLSRegistries[endpoint.URL.Host]; confirmedTLS {
				logrus.Debugf("Skipping non-TLS endpoint %s for host/port that appears to use TLS", endpoint.URL)
				continue
			}
		}

		logrus.Debugf("Trying to fetch image manifest of %s repository from %s %s", repoInfo.Name(), endpoint.URL, endpoint.Version)

		fetcher, err := newManifestFetcher(endpoint, repoInfo, authConfig, registryService)
		if err != nil {
			lastErr = err
			continue
		}

		if foundImages, err = fetcher.Fetch(ctx, namedRef); err != nil {
			// Was this fetch cancelled? If so, don't try to fall back.
			fallback := false
			select {
			case <-ctx.Done():
			default:
				if fallbackErr, ok := err.(fallbackError); ok {
					fallback = true
					confirmedV2 = confirmedV2 || fallbackErr.confirmedV2
					if fallbackErr.transportOK && endpoint.URL.Scheme == "https" {
						confirmedTLSRegistries[endpoint.URL.Host] = struct{}{}
					}
					err = fallbackErr.err
				}
			}
			if fallback {
				if _, ok := err.(distribution.ErrNoSupport); !ok {
					// Because we found an error that's not ErrNoSupport, discard all subsequent ErrNoSupport errors.
					discardNoSupportErrors = true
					// save the current error
					lastErr = err
				} else if !discardNoSupportErrors {
					// Save the ErrNoSupport error, because it's either the first error or all encountered errors
					// were also ErrNoSupport errors.
					lastErr = err
				}
				continue
			}
			logrus.Errorf("Not continuing with pull after error: %v", err)
			return nil, nil, err
		}

		if err := storeManifest(&foundImages, overwrite); err != nil {
			logrus.Errorf("Error storing manifests: %s\n", err)
		}
		return foundImages, repoInfo, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no endpoints found for %s\n", namedRef.String())
	}

	return nil, nil, lastErr

}

func newManifestFetcher(endpoint registry.APIEndpoint, repoInfo *registry.RepositoryInfo, authConfig types.AuthConfig, registryService registry.Service) (manifestFetcher, error) {
	switch endpoint.Version {
	case registry.APIVersion2:
		return &v2ManifestFetcher{
			endpoint:   endpoint,
			authConfig: authConfig,
			service:    registryService,
			repoInfo:   repoInfo,
		}, nil
	case registry.APIVersion1:
		return &v1ManifestFetcher{
			endpoint:   endpoint,
			authConfig: authConfig,
			service:    registryService,
			repoInfo:   repoInfo,
		}, nil
	}
	return nil, fmt.Errorf("unknown version %d for registry %s", endpoint.Version, endpoint.URL)
}

func makeImgManifestInspect(img *image.Image, tag string, mfInfo manifestInfo, mediaType string, tagList []string) *ImgManifestInspect {
	var digest string
	if err := mfInfo.digest.Validate(); err == nil {
		digest = mfInfo.digest.String()
	}
	var digests []string
	for _, blobDigest := range mfInfo.blobDigests {
		digests = append(digests, blobDigest.String())
	}
	return &ImgManifestInspect{
		Size:            mfInfo.length,
		MediaType:       mediaType,
		Tag:             tag,
		Digest:          digest,
		RepoTags:        tagList,
		Comment:         img.Comment,
		Created:         img.Created.Format(time.RFC3339Nano),
		ContainerConfig: &img.ContainerConfig,
		DockerVersion:   img.DockerVersion,
		Author:          img.Author,
		Config:          img.Config,
		Architecture:    img.Architecture,
		Os:              img.OS,
		Layers:          digests,
		Platform:        mfInfo.platform,
		CanonicalJSON:   mfInfo.jsonBytes,
	}
}

func continueOnError(err error) bool {
	switch v := err.(type) {
	case errcode.Errors:
		if len(v) == 0 {
			return true
		}
		return continueOnError(v[0])
	case distribution.ErrNoSupport:
		return continueOnError(v.Err)
	case errcode.Error:
		return shouldV2Fallback(v)
	case *client.UnexpectedHTTPResponseError:
		return true
	case ImageConfigPullError:
		return false
	case error:
		return !strings.Contains(err.Error(), strings.ToLower(syscall.ENOSPC.Error()))
	}
	// let's be nice and fallback if the error is a completely
	// unexpected one.
	// If new errors have to be handled in some way, please
	// add them to the switch above.
	return true
}
