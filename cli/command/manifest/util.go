package manifest

// list of valid os/arch values (see "Optional Environment Variables" section
// of https://golang.org/doc/install/source
// Added linux/s390x as we know System z support already exists

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/pkg/homedir"
	"github.com/opencontainers/go-digest"
)

type osArch struct {
	os   string
	arch string
}

//Remove any unsupported os/arch combo
var validOSArches = map[osArch]bool{
	osArch{os: "darwin", arch: "386"}:      true,
	osArch{os: "darwin", arch: "amd64"}:    true,
	osArch{os: "darwin", arch: "arm"}:      true,
	osArch{os: "darwin", arch: "arm64"}:    true,
	osArch{os: "dragonfly", arch: "amd64"}: true,
	osArch{os: "freebsd", arch: "386"}:     true,
	osArch{os: "freebsd", arch: "amd64"}:   true,
	osArch{os: "freebsd", arch: "arm"}:     true,
	osArch{os: "linux", arch: "386"}:       true,
	osArch{os: "linux", arch: "amd64"}:     true,
	osArch{os: "linux", arch: "arm"}:       true,
	osArch{os: "linux", arch: "arm64"}:     true,
	osArch{os: "linux", arch: "ppc64"}:     true,
	osArch{os: "linux", arch: "ppc64le"}:   true,
	osArch{os: "linux", arch: "mips64"}:    true,
	osArch{os: "linux", arch: "mips64le"}:  true,
	osArch{os: "linux", arch: "s390x"}:     true,
	osArch{os: "netbsd", arch: "386"}:      true,
	osArch{os: "netbsd", arch: "amd64"}:    true,
	osArch{os: "netbsd", arch: "arm"}:      true,
	osArch{os: "openbsd", arch: "386"}:     true,
	osArch{os: "openbsd", arch: "amd64"}:   true,
	osArch{os: "openbsd", arch: "arm"}:     true,
	osArch{os: "plan9", arch: "386"}:       true,
	osArch{os: "plan9", arch: "amd64"}:     true,
	osArch{os: "solaris", arch: "amd64"}:   true,
	osArch{os: "windows", arch: "386"}:     true,
	osArch{os: "windows", arch: "amd64"}:   true,
}

func isValidOSArch(os string, arch string) bool {
	// check for existence of this combo
	_, ok := validOSArches[osArch{os, arch}]
	return ok
}

func refToFilename(ref string) (string, error) {
	// @TODO :D
	return "test", nil
}

func getManifestFd(digest digest.Digest, transaction string) (*os.File, error) {

	newFile, err := mfToFilename(digest, transaction)
	if err != nil {
		return nil, err
	}

	fileInfo, err := os.Stat(newFile)
	if err != nil && !os.IsNotExist(err) {
		logrus.Debugf("Something went wrong trying to locate the manifest file: %s", err)
		return nil, err
	}

	if fileInfo == nil {
		return nil, nil
	}
	fd, err := os.Open(newFile)
	if err != nil {
		return nil, err
	}

	return fd, nil
}

func mfToFilename(digest digest.Digest, transaction string) (string, error) {
	// Store the manifests in a user's home to prevent conflict. The HOME dir needs to be set,
	// but can only be forcibly set on Linux at this time.
	// See https://github.com/docker/docker/pull/29478 for more background on why this approach
	// is being used.
	var dir string
	if err := ensureHomeIfIAmStatic(); err != nil {
		return "", err
	}
	userHome, err := homedir.GetStatic()
	if err != nil {
		return "", err
	}
	if transaction != "" {
		dir = fmt.Sprintf("%s/.docker/manifests/%s", userHome, transaction)
	} else {
		dir = fmt.Sprintf("%s/.docker/manifests/", userHome)
	}
	// Use the digest as the filename.
	return fmt.Sprintf("%s%s", dir, digest.Hex()), nil

}

func unmarshalIntoManifestInspect(fd *os.File) (ImgManifestInspect, error) {

	var newMf ImgManifestInspect
	theBytes := make([]byte, 10000)
	numRead, err := fd.Read(theBytes)
	if err != nil {
		return ImgManifestInspect{}, err
	}

	if err := json.Unmarshal(theBytes[:numRead], &newMf); err != nil {
		return ImgManifestInspect{}, err
	}

	return newMf, nil
}

func updateMfFile(mf ImgManifestInspect, transaction string) error {
	theBytes, err := json.Marshal(mf)
	if err != nil {
		return err
	}

	newFile, _ := mfToFilename(mf.Digest, transaction)
	//Rewrite the file
	fd, err := os.Create(newFile)
	defer fd.Close()
	if err != nil {
		return err
	}
	if _, err := fd.Write(theBytes); err != nil {
		return err
	}
	return nil
}
