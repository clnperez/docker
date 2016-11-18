package manifest

// list of valid os/arch values (see "Optional Environment Variables" section
// of https://golang.org/doc/install/source
// Added linux/s390x as we know System z support already exists

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"strings"

	"github.com/Sirupsen/logrus"
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

func getManifestFd(digest string) (*os.File, error) {

	newFile, err := mfToFilename(digest)
	if err != nil {
		return nil, err
	}

	fileInfo, err := os.Stat(newFile)
	if err != nil && !os.IsNotExist(err) {
		logrus.Debugf("Something went wrong trying to locate the manifest file: %s", err)
		return nil, err
	}

	if fileInfo == nil {
		// Don't create a new one
		/*
			fd, err := os.Create(newFile)
			if err != nil {
				fmt.Printf("Error creating %s: %s/n", newFile, err)
				return nil, err
			}
			return fd, nil
		*/
		return nil, nil
	}
	fd, err := os.Open(newFile)
	if err != nil {
		fmt.Printf("Error Opening manifest file: %s/n", err)
		return nil, err
	}

	return fd, nil
}

func mfToFilename(digest string) (string, error) {

	var (
		curUser *user.User
		err     error
	)

	if curUser, err = user.Current(); err != nil {
		fmt.Errorf("Error retreiving user: %s", err)
		return "", err
	}
	dir := fmt.Sprintf("%s/.docker/manifests/", curUser.HomeDir)
	// Use the digest as the filename. First strip the prefix.
	return fmt.Sprintf("%s%s", dir, strings.Split(digest, ":")[1]), nil
}

func unmarshalIntoManifestInspect(fd *os.File) (ImgManifestInspect, error) {

	var newMf ImgManifestInspect
	theBytes := make([]byte, 10000)
	numRead, err := fd.Read(theBytes)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", fd, err)
		return ImgManifestInspect{}, err
	}

	if err := json.Unmarshal(theBytes[:numRead], &newMf); err != nil {
		fmt.Printf("Unmarshal error: %s\n", err)
		return ImgManifestInspect{}, err
	}

	return newMf, nil
}

func updateMfFile(mf ImgManifestInspect) error {
	theBytes, err := json.Marshal(mf)
	if err != nil {
		fmt.Printf("Marshaling error: %s\n", err)
		return err
	}

	newFile, _ := mfToFilename(mf.Digest)
	//Rewrite the file
	fd, err := os.Create(newFile)
	defer fd.Close()
	if err != nil {
		fmt.Printf("Error opening file: %s", err)
		return err
	}
	if _, err := fd.Write(theBytes); err != nil {
		fmt.Printf("Error writing to file: %s", err)
		return err
	}
	return nil
}
