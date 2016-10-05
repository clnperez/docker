package manifest

import (
	"github.com/docker/distribution/manifest/manifestlist"
	containerTypes "github.com/docker/docker/api/types/container"
)

type ImageInspect struct {
	Size            int64
	MediaType       string
	Tag             string
	Digest          string
	RepoTags        []string
	Comment         string
	Created         string
	ContainerConfig *containerTypes.Config
	DockerVersion   string
	Author          string
	Config          *containerTypes.Config
	Architecture    string
	Os              string
	Layers          []string
	Platform        manifestlist.PlatformSpec
	CanonicalJson   []byte
}
