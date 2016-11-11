package main

import (

	"github.com/docker/docker/pkg/integration/checker"
	"github.com/go-check/check"
)

const (
	privateRegistryURL0 = "127.0.0.1:5000"
	privateRegistryURL1 = "127.0.0.1:5001"
	privateRegistryURL2 = "127.0.0.1:5002"
	privateRegistryURL3 = "127.0.0.1:5003"
	privateRegistryURL4 = "127.0.0.1:5004"

	binaryV1 = "docker-registry"
	binaryV2 = "registry-v2"
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

        s.regV1 = setupRegistryV1At(c, false, privateRegistryURL0)
        s.regV2 = setupRegistry(c, false, "", privateRegistryURL1)
        s.regV2Schema1 = setupRegistry(c, true, "", privateRegistryURL2)
        s.regV1WithAuth = setupRegistryV1At(c, true, privateRegistryURL3)
        s.regV2WithAuth = setupRegistry(c, false, "htpasswd", privateRegistryURL4)

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

// if a registry adds a manifest-list this test will no longer pass, hmm
// tests a manifest fetch on a repo without a manifest-list
func (s *DockerManifestSuite) TestManifestFetchWithoutList(c *check.C) {
        testRequires(c, DaemonIsLinux)
	out, _ := dockerCmd(c, "manifest", "fetch", "busybox:latest")

	c.Assert(out, checker.Contains, "literally nothing")

}
// tests a manifest fetch on an unknown image
func (s *DockerManifestSuite) TestManifestFetchOnUnkownImage(c *check.C) {
	testRequires(c, DaemonIsLinux)
	unknownImage := "busybox:thisdoesntexist"

	// going to have to test with error here
	_, _, err := dockerCmdWithError("manifest", "fetch", unknownImage)

	c.Assert(err, checker.Contains, "not found in repository docker.io/library/busybox")
}


func setupRegistryV1At(c *check.C, auth bool, url string) *testRegistryV1 {
	return &testRegistryV1{
		url: url,
	}
}
