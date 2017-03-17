package manifest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/opencontainers/go-digest"
	"golang.org/x/net/context"

	"github.com/docker/distribution/reference"
	"github.com/docker/distribution/registry/api/errcode"
	"github.com/docker/distribution/registry/client"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/cli"
	"github.com/docker/docker/cli/command"
	"github.com/docker/docker/distribution"
	"github.com/docker/docker/dockerversion"
	"github.com/docker/docker/image"
	"github.com/docker/docker/pkg/homedir"
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
	named, err := reference.ParseNormalizedName(opts.remote)
	if err != nil {
		return err
	}
	// This could be a single manifest or manifest list
	_, _, err := getImageData(dockerCli, named.Name(), "", true)
	if err != nil {
		return err
	}
	return nil
}

func loadManifest(manifest string, transaction string) ([]ImgManifestInspect, error) {
	return nil, nil
}

func storeManifest(imgInspect []ImgManifestInspect, transaction string, overwrite bool) error {
	// Store this image manifest so that it can be annotated.

	var (
		err    error
		fd     *os.File
		newDir string
	)

	// Store the manifests in a user's home to prevent conflict. The HOME dir needs to be set,
	// but can only be forcibly set on Linux at this time.
	// See https://github.com/docker/docker/pull/29478 for more background on why this approach
	// is being used.
	if err := ensureHomeIfIAmStatic(); err != nil {
		return err
	}
	userHome, err := homedir.GetStatic()
	if transaction == "" {
		newDir = fmt.Sprintf("%s/.docker/manifests/", userHome)
	} else {
		newDir = fmt.Sprintf("%s/.docker/manifests/%s", userHome, transaction)
	}
	os.MkdirAll(newDir, 0755)
	for i, mf := range *imgInspect {
		fd, err = getManifestFd(mf.Digest, transaction)
		if err != nil {
			return err
		}
		defer fd.Close()
		if err != nil {
			fmt.Printf("Store manifests: getManifestFd err: %s\n", err)
			return err
		}
		if fd != nil && overwrite == false {
			logrus.Debug("Not overwriting existing manifest file")
			localMfstInspect, err := unmarshalIntoManifestInspect(fd)
			if err != nil {
				fmt.Printf("Store: Marshal error for %s: %s\n", mf.Tag, err)
				return err
			}
			(*imgInspect)[i] = localMfstInspect
			continue
		} else {
			if err = updateMfFile(mf, transaction); err != nil {
				// update overwrites, so can be used to make a new copy
				fmt.Printf("Error writing new local manifest copy: %s\n", err)
				return err
			}
		}
	}

	return nil
}

func getImageData(dockerCli *command.DockerCli, name string, transactionID string, pullRemote bool) ([]ImgManifestInspect, *registry.RepositoryInfo, error) {

	var (
		lastErr                error
		discardNoSupportErrors bool
		foundImages            []ImgManifestInspect
		confirmedV2            bool
		confirmedTLSRegistries = make(map[string]struct{})
		namedRef               reference.Named
		err                    error
	)

	if namedRef, err = reference.ParseNormalizedNamed(name); err != nil {
		return nil, nil, fmt.Errorf("Error parsing reference for %s: %s\n", name, err)
	}
	logrus.Debugf("getting image data for ref: %v", namedRef)
	// Make sure it has a tag, as long as it's not a digest
	if _, isDigested := namedRef.(reference.Canonical); !isDigested {
		namedRef = reference.TagNameOnly(namedRef)
	}

	// Resolve the Repository name from fqn to RepositoryInfo
	// This calls TrimNamed, which removes the tag, so always use namedRef for the image.
	repoInfo, err := registry.ParseRepositoryInfo(namedRef)
	if err != nil {
		return nil, nil, err
	}

	// First check to see if stored locally, either in an ongoing transaction, or a single manfiest:
	if !pullRemote { // if fetching, always just pull & store
		foundImages, err = loadManifests(namedRef.Name(), transactionID)
		if err != nil {
			return nil, nil, err
		}
		// Great, no reason to pull from the registry.
		if len(foundImages) > 0 {
			return foundImages, repoInfo, nil
		}
	}

	ctx := context.Background()

	authConfig := command.ResolveAuthConfig(ctx, dockerCli, repoInfo.Index)

	options := registry.ServiceOptions{}
	registryService := registry.NewService(options)

	// a list of registry.APIEndpoint, which could be mirrors, etc., of locally-configured
	// repo endpoints. The list will be ordered by priority (v2, https, v1).
	endpoints, err := registryService.LookupPullEndpoints(reference.Domain(repoInfo.Name))
	if err != nil {
		return nil, nil, err
	}
	logrus.Debugf("manifest pull: endpoints: %v", endpoints)

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

		logrus.Debugf("Trying to fetch image manifest of %s repository from %s %s", namedRef, endpoint.URL, endpoint.Version)

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

		if err := storeManifest(foundImages, transactionID); err != nil {
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

func makeImgManifestInspect(name string, img *image.Image, tag string, mfInfo manifestInfo, mediaType string, tagList []string) *ImgManifestInspect {
	var digest digest.Digest
	if err := mfInfo.digest.Validate(); err == nil {
		digest = mfInfo.digest
	}
	var digests []string
	for _, blobDigest := range mfInfo.blobDigests {
		digests = append(digests, blobDigest.String())
	}
	return &ImgManifestInspect{
		NormalName:      name,
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
