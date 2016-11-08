package manifest

import (
	"github.com/docker/distribution/manifest/manifestlist"
	containerTypes "github.com/docker/docker/api/types/container"
)

// fallbackError wraps an error that can possibly allow fallback to a different
// endpoint.
type fallbackError struct {
	// err is the error being wrapped.
	err error
	// confirmedV2 is set to true if it was confirmed that the registry
	// supports the v2 protocol. This is used to limit fallbacks to the v1
	// protocol.
	confirmedV2 bool
	transportOK bool
}

// Error renders the FallbackError as a string.
func (f fallbackError) Error() string {
	return f.err.Error()
}

// ImgManifestInspect contains info to output for a manifest object.
type ImgManifestInspect struct {
	Size            int64                  `json:size`
	MediaType       string                 `json:media_type`
	Tag             string                 `json:tag`
	Digest          string                 `json:digest`
	RepoTags        []string               `json:repotags`
	Comment         string                 `json:comment`
	Created         string                 `json:created`
	ContainerConfig *containerTypes.Config `json:container_config`
	DockerVersion   string                 `json:docker_version`
	Author          string                 `json:author`
	Config          *containerTypes.Config `json:config`
	// PlatformSpec has Arch & OS, so why twice?
	Architecture  string                    `json:architecture`
	Os            string                    `json:os`
	Layers        []string                  `json:layers`
	Platform      manifestlist.PlatformSpec `json:platform`
	CanonicalJSON []byte                    `json:"-"`
}
