package main

import (
	//"fmt"

	"github.com/docker/docker/pkg/integration/checker"
	"github.com/go-check/check"
)

const (
	privateRegistryURLV1     = "127.0.0.1:5000"
	privateRegistryURLV2     = "127.0.0.1:5001"
	privateRegistryURLV2Sch1 = "127.0.0.1:5002"
	privateRegistryURLV1Auth = "127.0.0.1:5003"
	privateRegistryURLV2Auth = "127.0.0.1:5004"

	binaryV1        = "docker-registry"
	binaryV2        = "registry-v2"
	binaryV2Schema1 = "registry-v2-schema1"
)

func init() {
	check.Suite(&DockerManifestSuite{
		ds: &DockerSuite{},
	})
}

//TODO: see what docker already does
// regarding testingreg v1
type testRegistryV1 struct {
	//	cmd *exec.Cmd
	url string
	dir string
}

type DockerManifestSuite struct {
	ds            *DockerSuite
	regV1         *testRegistryV1
	regV2         *testRegistryV2
	regV2Schema1  *testRegistryV2
	regV1WithAuth *testRegistryV1
	regV2WithAuth *testRegistryV2
}

func (s *DockerManifestSuite) SetUpSuite(c *check.C) {
	// can't think of anything
}

func (s *DockerManifestSuite) TearDownSuite(c *check.C) {
	// can't think of anything here either
}

func (s *DockerManifestSuite) SetUpTest(c *check.C) {

	s.regV1 = setupRegistryV1At(c, false, privateRegistryURLV1)
	s.regV2 = setupRegistry(c, false, "", privateRegistryURLV2)
	s.regV2Schema1 = setupRegistry(c, true, "", privateRegistryURLV2Sch1)
	s.regV1WithAuth = setupRegistryV1At(c, true, privateRegistryURLV1Auth)
	s.regV2WithAuth = setupRegistry(c, false, "htpasswd", privateRegistryURLV2Auth)

}

func (s *DockerManifestSuite) TearDownTest(c *check.C) {
	// not checking V1 registries now
	if s.regV2 != nil {
		s.regV2.Close()
	}
	if s.regV2Schema1 != nil {
		s.regV2Schema1.Close()
	}
	if s.regV2WithAuth != nil {
		// docker logout of registry? probably look how this is done in reg suite
		s.regV2WithAuth.Close()
	}

	s.ds.TearDownTest(c)

}

func (s *DockerManifestSuite) TestManifestFetchWithoutList(c *check.C) {
	testRequires(c, DaemonIsLinux)
	_, errCode := dockerCmd(c, "manifest", "fetch", "busybox:latest")

	c.Assert(errCode, checker.Equals, 0)

}

// tests a manifest inspect
func (s *DockerManifestSuite) TestManifestInspect(c *check.C) {
	testRequires(c, DaemonIsLinux)
	image := "busybox:latest"

	out, rc, _ := dockerCmdWithError("manifest", "inspect", image)
	c.Assert(rc, checker.Equals, 0)
	// @TODO: Put better inpsect verification in when there's better output.
	c.Assert(out, checker.Contains, "sha256")
}

// tests a manifest fetch on an unknown image
func (s *DockerManifestSuite) TestManifestFetchOnUnkownImage(c *check.C) {
	testRequires(c, DaemonIsLinux)
	unknownImage := "busybox:thisdoesntexist"

	// going to have to test with error here
	out, _, _ := dockerCmdWithError("manifest", "fetch", unknownImage)

	c.Assert(out, checker.Contains, "manifest unknown")
}

func (s *DockerManifestSuite) TestManifestAnnotate(c *check.C) {
	testRequires(c, DaemonIsLinux)
	// Since annotate changes a local manifest, no need for a registry
	_, rc := dockerCmd(c, "manifest", "annotate", "busybox", "--arch", "amd64", "--os", "linux", "--cpuFeatures", "sse")
	c.Assert(rc, checker.Equals, 0)
}

func setupRegistryV1At(c *check.C, auth bool, url string) *testRegistryV1 {
	return &testRegistryV1{
		url: url,
	}
}
