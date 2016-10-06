package manifest

import (
	"encoding/json"
	"fmt"
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
)

type fetchOptions struct {
	remote string
	raw    bool
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

	flags := cmd.Flags()

	flags.BoolVarP(&opts.raw, "raw", "r", false, "Provide raw JSON output")
	command.AddTrustedFlags(flags, true)

	return cmd
}

func runListFetch(dockerCli *command.DockerCli, opts fetchOptions) error {
	// Get the data and then format it
	name := opts.remote
	imgInspect, _, err := getImageData(dockerCli, name)
	if err != nil {
		logrus.Fatal(err)
	}
	if opts.raw == true {
		out, err := json.Marshal(imgInspect)
		if err != nil {
			logrus.Fatal(err)
		}
		fmt.Println(string(out))
		return nil
	}
	// output basic informative details about the image
	if len(imgInspect) == 1 {
		// this is a basic single manifest
		fmt.Printf("%s: manifest type: %s\n", name, imgInspect[0].MediaType)
		fmt.Printf("      Digest: %s\n", imgInspect[0].Digest)
		fmt.Printf("Architecture: %s\n", imgInspect[0].Architecture)
		fmt.Printf("          OS: %s\n", imgInspect[0].Os)
		fmt.Printf("    # Layers: %d\n", len(imgInspect[0].Layers))
		for i, digest := range imgInspect[0].Layers {
			fmt.Printf("      layer %d: digest = %s\n", i+1, digest)
		}
		return nil
	}
	// More than one response. This is a manifest list.
	fmt.Printf("%s is a manifest list containing the following %d manifest references:\n", name, len(imgInspect))
	for i, img := range imgInspect {
		fmt.Printf("%d    Mfst Type: %s\n", i+1, img.MediaType)
		fmt.Printf("%d       Digest: %s\n", i+1, img.Digest)
		fmt.Printf("%d  Mfst Length: %d\n", i+1, img.Size)
		fmt.Printf("%d     Platform:\n", i+1)
		fmt.Printf("%d           -      OS: %s\n", i+1, img.Platform.OS)
		// WINDOWS SUPPORT - NOT VENDORED YET fmt.Printf("%d           - OS Vers: %s\n", i+1, img.Platform.OSVersion)
		// WINDOWS SUPPORT - NOT VENDORED YET fmt.Printf("%d           - OS Feat: %s\n", i+1, img.Platform.OSFeatures)
		fmt.Printf("%d           -    Arch: %s\n", i+1, img.Platform.Architecture)
		fmt.Printf("%d           - Variant: %s\n", i+1, img.Platform.Variant)
		fmt.Printf("%d           - Feature: %s\n", i+1, strings.Join(img.Platform.Features, ","))
		fmt.Printf("%d     # Layers: %d\n", i+1, len(img.Layers))
		for j, digest := range img.Layers {
			fmt.Printf("         layer %d: digest = %s\n", j+1, digest)
		}
		fmt.Println()
	}
	return nil
}

func getImageData(dockerCli *command.DockerCli, name string) ([]ImgManifestInspect, *registry.RepositoryInfo, error) {

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

		return foundImages, repoInfo, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no endpoints found for %s", namedRef.String())
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
