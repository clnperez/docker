package manifest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"

	digest "github.com/opencontainers/go-digest"

	"github.com/docker/distribution/manifest/manifestlist"
	"github.com/docker/distribution/registry/api/v2"
	"github.com/docker/distribution/registry/client/auth"
	"github.com/docker/distribution/registry/client/transport"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/cli"
	"github.com/docker/docker/cli/command"
	"github.com/docker/docker/cli/config/configfile"
	"github.com/docker/docker/dockerversion"
	"github.com/docker/docker/pkg/homedir"
	"github.com/docker/docker/reference"
	"github.com/docker/docker/registry"
)

type createOpts struct {
	newRef string
}

type existingTokenHandler struct {
	token string
}

func (th *existingTokenHandler) AuthorizeRequest(req *http.Request, params map[string]string) error {
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", th.token))
	return nil
}

func (th *existingTokenHandler) Scheme() string {
	return "bearer"
}

type dumbCredentialStore struct {
	auth *types.AuthConfig
}

// YAMLInput represents the YAML format input to the pushml
// command.
type YAMLInput struct {
	Image     string
	Manifests []Entry
}

// Entry represents an entry in the list of manifests to
// be combined into a manifest list, provided via the YAML input
type Entry struct {
	Image    string
	Platform manifestlist.PlatformSpec
}

// we will store up a list of blobs we must ask the registry
// to cross-mount into our target namespace
type blobMount struct {
	FromRepo string
	Digest   string
}

// if we have mounted blobs referenced from manifests from
// outside the target repository namespace we will need to
// push them to our target's repo as they will be references
// from the final manifest list object we push
type manifestPush struct {
	Name      string
	Digest    string
	JSONBytes []byte
	MediaType string
}

func newCreateListCommand(dockerCli *command.DockerCli) *cobra.Command {

	opts := createOpts{}

	cmd := &cobra.Command{
		Use:   "create --name newRef manifest [manifest...]",
		Short: "Push a manifest list for an image to a repository",
		Args:  cli.RequiresMinArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return putManifestList(dockerCli, opts, args)
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&opts.newRef, "name", "n", "", "")
	return cmd
}

func putManifestList(dockerCli *command.DockerCli, opts createOpts, manifests []string) error {
	var (
		manifestList      manifestlist.ManifestList
		blobMountRequests []blobMount
		manifestRequests  []manifestPush
	)

	targetRef, err := reference.ParseNamed(opts.newRef)
	if err != nil {
		return fmt.Errorf("Error parsing name for manifest list (%s): %v", opts.newRef, err)
	}
	targetRepo, err := registry.ParseRepositoryInfo(targetRef)
	if err != nil {
		return fmt.Errorf("Error parsing repository name for manifest list (%s): %v", opts.newRef, err)
	}
	targetEndpoint, repoName, err := setupRepo(targetRepo)
	if err != nil {
		return fmt.Errorf("Error setting up repository endpoint and references for %q: %v", targetRef, err)
	}

	ctx := context.Background()

	// Now create the manifest list payload by looking up the manifest schemas
	// for the constituent images:

	// @TODO: Pull from local files. Create func to do that (and use it in inspect as well.)
	logrus.Info("Retrieving digests of images...")
	for _, manifestRef := range manifests {

		mfstData, repoInfo, err := getImageData(dockerCli, manifestRef, false)
		if err != nil {
			return err
		}
		if repoInfo.Hostname() != targetRepo.Hostname() {
			return fmt.Errorf("Cannot use source images from a different registry than the target image: %s != %s", repoInfo.Hostname(), targetRepo.Hostname())
		}

		if len(mfstData) > 1 {
			// too many responses--can only happen if a manifest list was returned for the name lookup
			return fmt.Errorf("You specified a manifest list entry from a digest that points to a current manifest list. Manifest lists do not allow recursion.")
		}

		mfstInspect := mfstData[0]
		manifest := manifestlist.ManifestDescriptor{
			Platform: mfstInspect.Platform,
		}
		manifest.Descriptor.Digest = mfstInspect.Digest
		manifest.Size = mfstInspect.Size
		manifest.MediaType = mfstInspect.MediaType

		err = manifest.Descriptor.Digest.Validate()
		if err != nil {
			return fmt.Errorf("Digest parse of image %q failed with error: %v", manifestRef, err)
		}

		logrus.Infof("Image %q is digest %s; size: %d", manifestRef, mfstInspect.Digest, mfstInspect.Size)

		// if this image is in a different repo, we need to add the layer/blob digests to the list of
		// requested blob mounts (cross-repository push) before pushing the manifest list
		if repoName != repoInfo.RemoteName() {
			logrus.Debugf("Adding layers of %q to blob mount requests", manifestRef)
			for _, layer := range mfstInspect.Layers {
				blobMountRequests = append(blobMountRequests, blobMount{FromRepo: repoInfo.RemoteName(), Digest: layer})
			}
			// also must add the manifest to be pushed in the target namespace
			logrus.Debugf("Adding manifest %q -> to be pushed to %q as a manifest reference", repoInfo.RemoteName(), repoName)
			manifestRequests = append(manifestRequests, manifestPush{
				Name:      repoInfo.RemoteName(),
				Digest:    mfstInspect.Digest.String(),
				JSONBytes: mfstInspect.CanonicalJSON,
				MediaType: mfstInspect.MediaType,
			})
		}
		manifestList.Manifests = append(manifestList.Manifests, manifest)
	}

	// Set the schema version
	manifestList.Versioned = manifestlist.SchemaVersion

	urlBuilder, err := v2.NewURLBuilderFromString(targetEndpoint.URL.String(), false)
	logrus.Infof("manifest: put: target endpoint url: %s", targetEndpoint.URL.String())
	if err != nil {
		return fmt.Errorf("Can't create URL builder from endpoint (%s): %v", targetEndpoint.URL.String(), err)
	}
	pushURL, err := createManifestURLFromRef(targetRef, urlBuilder)
	if err != nil {
		return fmt.Errorf("Error setting up repository endpoint and references for %q: %v", targetRef, err)
	}
	logrus.Debugf("Manifest list push url: %s", pushURL)

	deserializedManifestList, err := manifestlist.FromDescriptors(manifestList.Manifests)
	if err != nil {
		return fmt.Errorf("Cannot deserialize manifest list: %v", err)
	}
	mediaType, p, err := deserializedManifestList.Payload()
	logrus.Debugf("mediaType of manifestList: %s", mediaType)
	if err != nil {
		return fmt.Errorf("Cannot retrieve payload for HTTP PUT of manifest list: %v", err)

	}
	putRequest, err := http.NewRequest("PUT", pushURL, bytes.NewReader(p))
	if err != nil {
		return fmt.Errorf("HTTP PUT request creation failed: %v", err)
	}
	putRequest.Header.Set("Content-Type", mediaType)

	httpClient, err := getHTTPClient(ctx, dockerCli, targetRepo, targetEndpoint, repoName)
	if err != nil {
		return fmt.Errorf("Failed to setup HTTP client to repository: %v", err)
	}

	// before we push the manifest list, if we have any blob mount requests, we need
	// to ask the registry to mount those blobs in our target so they are available
	// as references
	if err := mountBlobs(httpClient, urlBuilder, targetRef, blobMountRequests); err != nil {
		return fmt.Errorf("Couldn't mount blobs for cross-repository push: %v", err)
	}

	// we also must push any manifests that are referenced in the manifest list into
	// the target namespace
	if err := pushReferences(httpClient, urlBuilder, targetRef, manifestRequests); err != nil {
		return fmt.Errorf("Couldn't push manifests referenced in our manifest list: %v", err)
	}

	resp, err := httpClient.Do(putRequest)
	if err != nil {
		return fmt.Errorf("V2 registry PUT of manifest list failed: %v", err)
	}
	defer resp.Body.Close()

	if statusSuccess(resp.StatusCode) {
		dgstHeader := resp.Header.Get("Docker-Content-Digest")
		dgst, err := digest.Parse(dgstHeader)
		if err != nil {
			return err
		}
		logrus.Info("Succesfully pushed manifest list %s with digest %s", targetRef, dgst)
		return nil
	}
	return fmt.Errorf("Registry push unsuccessful: response %d: %s", resp.StatusCode, resp.Status)
}

func getHTTPClient(ctx context.Context, dockerCli *command.DockerCli, repoInfo *registry.RepositoryInfo, endpoint registry.APIEndpoint, repoName string) (*http.Client, error) {
	// get the http transport, this will be used in a client to upload manifest
	// TODO - add separate function get client
	base := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     endpoint.TLSConfig,
		DisableKeepAlives:   true,
	}

	authConfig := command.ResolveAuthConfig(ctx, dockerCli, repoInfo.Index)
	modifiers := registry.DockerHeaders(dockerversion.DockerUserAgent(nil), http.Header{})
	authTransport := transport.NewTransport(base, modifiers...)
	challengeManager, _, err := registry.PingV2Registry(endpoint.URL, authTransport)
	if err != nil {
		return nil, fmt.Errorf("Ping of V2 registry failed: %v", err)
	}
	if authConfig.RegistryToken != "" {
		passThruTokenHandler := &existingTokenHandler{token: authConfig.RegistryToken}
		modifiers = append(modifiers, auth.NewAuthorizer(challengeManager, passThruTokenHandler))
	} else {
		creds := registry.NewStaticCredentialStore(&authConfig)
		tokenHandler := auth.NewTokenHandler(authTransport, creds, repoName, "*")
		basicHandler := auth.NewBasicHandler(creds)
		modifiers = append(modifiers, auth.NewAuthorizer(challengeManager, tokenHandler, basicHandler))
	}
	tr := transport.NewTransport(base, modifiers...)

	httpClient := &http.Client{
		Transport: tr,
		// @TODO: Use the default (leave CheckRedirect nil), or write a generic one
		// and put it somewhere? (There's one in docker/distribution/registry/client/repository.go)
		// CheckRedirect: checkHTTPRedirect,
	}
	return httpClient, nil
}

func createManifestURLFromRef(targetRef reference.Named, urlBuilder *v2.URLBuilder) (string, error) {
	// get rid of hostname so the target URL is constructed properly
	_, name := splitHostname(targetRef.String())
	targetRef, err := reference.ParseNamed(name)
	if err != nil {
		return "", fmt.Errorf("Can't parse target image repository name from reference: %v", err)
	}

	// Set the tag to latest, if no tag found
	if _, isTagged := targetRef.(reference.NamedTagged); !isTagged {
		targetRef, err = reference.WithTag(targetRef, reference.DefaultTag)
		if err != nil {
			return "", fmt.Errorf("Error adding default tag to target repository name: %v", err)
		}
	} else {
		tagged, _ := targetRef.(reference.NamedTagged)
		targetRef, err = reference.WithTag(targetRef, tagged.Tag())
		if err != nil {
			return "", fmt.Errorf("Error referencing specified tag to target repository name: %v", err)
		}
	}

	manifestURL, err := urlBuilder.BuildManifestURL(targetRef)
	if err != nil {
		return "", fmt.Errorf("Failed to build manifest URL from target reference: %v", err)
	}
	return manifestURL, nil
}

func setupRepo(repoInfo *registry.RepositoryInfo) (registry.APIEndpoint, string, error) {
	endpoint, err := selectPushEndpoint(repoInfo)
	if err != nil {
		return endpoint, "", err
	}
	logrus.Debugf("manifest: create: endpoint: %v", endpoint)
	repoName := repoInfo.FullName()
	// If endpoint does not support CanonicalName, use the RemoteName instead
	if endpoint.TrimHostname {
		repoName = repoInfo.RemoteName()
		logrus.Debugf("repoName: %v", repoName)
	}
	return endpoint, repoName, nil
}

func selectPushEndpoint(repoInfo *registry.RepositoryInfo) (registry.APIEndpoint, error) {
	options := registry.ServiceOptions{}
	// By default (unless deprecated), loopback (IPv4 at least...) is automatically added as an insecure registry.
	options.InsecureRegistries = loadLocalInsecureRegistries()
	registryService := registry.NewService(options)
	endpoints, err := registryService.LookupPushEndpoints(repoInfo.Hostname())
	if err != nil {
		return registry.APIEndpoint{}, err
	}
	logrus.Debugf("manifest: potential push endpoints: %v\n", endpoints)
	// Default to the highest priority endpoint to return
	endpoint := endpoints[0]
	if !repoInfo.Index.Secure {
		for _, ep := range endpoints {
			if ep.URL.Scheme == "http" {
				endpoint = ep
			}
		}
	}
	return endpoint, nil
}

func loadLocalInsecureRegistries() []string {
	// Store in $HOME/.docker/config.json. There may be mismatches between what the user has in their
	// local config and what the daemon they're talking to allows, but we can be okay with that.
	userHome, err := homedir.GetStatic()
	if err != nil {
		logrus.Debugf("Manifest create: Unable to retreive $HOME")
		return []string{}
	}

	jsonData, err := ioutil.ReadFile(fmt.Sprintf("%s/.docker/config.json", userHome))
	if err != nil && !os.IsNotExist(err) {
		logrus.Debugf("Manifest create: Unable to read $HOME/.docker/config.json: %s", err)
		return []string{}
	}

	if jsonData != nil {
		cf := configfile.ConfigFile{}
		if err := json.Unmarshal(jsonData, &cf); err != nil {
			logrus.Debugf("Manifest create: Unable to unmarshal insecure registries from $HOME/.docker/config.json: %s", err)
			return []string{}
		}
		insecureRegistries := cf.InsecureRegistries
		if insecureRegistries != nil {
			// @TODO: Add some hostname/ip validation somewhere
			// @TODO: Add a test for a) specifying in config.json, b) invalid entries
			return insecureRegistries
		}
	}

	logrus.Debugf("Manifest create: Unable to load insecure registries from $HOME/.docker/config.json")
	return []string{}
}

func pushReferences(httpClient *http.Client, urlBuilder *v2.URLBuilder, ref reference.Named, manifests []manifestPush) error {
	pushTarget := ref.Name()
	for i, manifest := range manifests {
		// create a dummy tag from the integer count and the original name (in the original repo)
		targetRef, err := reference.ParseNamed(fmt.Sprintf("%s:%d%s", pushTarget, i, strings.Replace(manifest.Name, "/", "_", -1)))
		if err != nil {
			return fmt.Errorf("Error creating manifest name target for referenced manifest %q: %v", manifest.Name, err)
		}
		pushURL, err := createManifestURLFromRef(targetRef, urlBuilder)
		if err != nil {
			return fmt.Errorf("Error setting up manifest push URL for manifest references for %q: %v", manifest.Name, err)
		}
		logrus.Debugf("manifest reference push URL: %s", pushURL)

		pushRequest, err := http.NewRequest("PUT", pushURL, bytes.NewReader(manifest.JSONBytes))
		if err != nil {
			return fmt.Errorf("HTTP PUT request creation for manifest reference push failed: %v", err)
		}
		pushRequest.Header.Set("Content-Type", manifest.MediaType)
		resp, err := httpClient.Do(pushRequest)
		if err != nil {
			return fmt.Errorf("PUT of manifest reference failed: %v", err)
		}

		resp.Body.Close()
		if !statusSuccess(resp.StatusCode) {
			return fmt.Errorf("Referenced manifest push unsuccessful: response %d: %s", resp.StatusCode, resp.Status)
		}
		dgstHeader := resp.Header.Get("Docker-Content-Digest")
		dgst, err := digest.Parse(dgstHeader)
		if err != nil {
			return fmt.Errorf("Couldn't parse pushed manifest digest response: %v", err)
		}
		if string(dgst) != manifest.Digest {
			return fmt.Errorf("Pushed referenced manifest received a different digest: expected %s, got %s", manifest.Digest, string(dgst))
		}
		logrus.Debugf("referenced manifest %q pushed; digest matches: %s", manifest.Name, string(dgst))
	}
	return nil
}

func mountBlobs(httpClient *http.Client, urlBuilder *v2.URLBuilder, ref reference.Named, blobsRequested []blobMount) error {
	// get rid of hostname so the target URL is constructed properly
	_, name := splitHostname(ref.String())
	targetRef, _ := reference.ParseNamed(name)

	for _, blob := range blobsRequested {
		// create URL request
		url, err := urlBuilder.BuildBlobUploadURL(targetRef, url.Values{"from": {blob.FromRepo}, "mount": {blob.Digest}})
		if err != nil {
			return fmt.Errorf("Failed to create blob mount URL: %v", err)
		}
		mountRequest, err := http.NewRequest("POST", url, nil)
		if err != nil {
			return fmt.Errorf("HTTP POST request creation for blob mount failed: %v", err)
		}
		mountRequest.Header.Set("Content-Length", "0")
		resp, err := httpClient.Do(mountRequest)
		if err != nil {
			return fmt.Errorf("V2 registry POST of blob mount failed: %v", err)
		}

		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			return fmt.Errorf("Blob mount failed to url %s: HTTP status %d", url, resp.StatusCode)
		}
		logrus.Debugf("Mount of blob %s succeeded, location: %q", blob.Digest, resp.Header.Get("Location"))
	}
	return nil
}

func statusSuccess(status int) bool {
	return status >= 200 && status <= 399
}

// splitHostname splits a repository name to hostname and remotename string.
// If no valid hostname is found, the default hostname is used. Repository name
// needs to be already validated before.
func splitHostname(name string) (hostname, remoteName string) {
	i := strings.IndexRune(name, '/')
	if i == -1 || (!strings.ContainsAny(name[:i], ".:") && name[:i] != "localhost") {
		hostname, remoteName = reference.DefaultHostname, name
	} else {
		hostname, remoteName = name[:i], name[i+1:]
	}
	if hostname == reference.LegacyDefaultHostname {
		hostname = reference.DefaultHostname
	}
	if hostname == reference.DefaultHostname && !strings.ContainsRune(remoteName, '/') {
		remoteName = reference.DefaultRepoPrefix + remoteName
	}
	return
}
