package manifest

import (
	"encoding/json"
	//"errors"
	"fmt"
	"os"
	"os/user"
	"strings"

	"github.com/Sirupsen/logrus"

	/*
		"golang.org/x/net/context"

		"github.com/docker/distribution/registry/api/errcode"
		"github.com/docker/distribution/registry/client"
		"github.com/docker/docker/api/types"
		"github.com/docker/docker/cli"
		"github.com/docker/docker/dockerversion"
		"github.com/docker/docker/image"
	*/
	"github.com/docker/docker/cli"
	"github.com/docker/docker/cli/command"
	"github.com/spf13/cobra"
)

type annotateOptions struct {
	remote   string
	variants []string
	features []string
}

// NewAnnotateCommand creates a new `docker manifest inspect` command
func newAnnotateCommand(dockerCli *command.DockerCli) *cobra.Command {
	var opts annotateOptions

	cmd := &cobra.Command{
		Use:   "annotate NAME[:TAG] [OPTIONS]",
		Short: "Add additional information to an image's manifest.",
		Args:  cli.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.remote = args[0]
			return runManifestAnnotate(dockerCli, opts)
		},
	}

	flags := cmd.Flags()

	// @TODO: Should we do any validation? We can't have an exhaustive list
	// of features, but at least check for only a csv of alpha-chars?
	flags.StringSliceVarP(&opts.features, "features", "f", []string{}, "Add feature metadata to a manifest before pushing it.")
	flags.StringSliceVarP(&opts.variants, "variants", "v", []string{}, "Add arch variants to a manifest before pushing it.")

	command.AddTrustedFlags(flags, true)

	return cmd
}

func runManifestAnnotate(dockerCli *command.DockerCli, opts annotateOptions) error {

	/*
		for _, flag := range opts.features {
			fmt.Printf("Feature flags:%s \n", flag)
		}
		for _, flag := range opts.variants {
			fmt.Printf("Variant flags:%s \n", flag)
		}
	*/

	var (
		fd      *os.File
		curUser *user.User
	)

	// Make sure the manifests are pulled, find the file you need, unmarshal the json, edit the file, and done.
	imgInspect, _, err := getImageData(dockerCli, opts.remote)
	if err != nil {
		return err
	}

	if len(imgInspect) != 1 {
		return fmt.Errorf("Cannot annotate manifest list. Please pass an image name")
	}

	if err := storeManifest(imgInspect, false); err != nil {
		fmt.Printf("Error storing manifests for annotating: %s\n", err)
		return err
	}

	mf := imgInspect[0]
	if curUser, err = user.Current(); err != nil {
		fmt.Errorf("Error retreiving user: %s", err)
		return err
	}
	dir := fmt.Sprintf("%s/.docker/manifests/", curUser.HomeDir)
	// Use the digest as the filename. First strip the prefix.
	newFile := fmt.Sprintf("%s%s", dir, strings.Split(mf.Digest, ":")[1])
	fileInfo, err := os.Stat(newFile)
	if err != nil || os.IsNotExist(err) {
		logrus.Debugf("Something went wrong trying to locate the manifest file: %s", err)
		return err
	}
	if fileInfo == nil {
		fmt.Print("This shouldn't be possible. Assert?\n")
	}

	// Now unmarshal the json
	var newMf ImgManifestInspect
	defer fd.Close()

	fd, err = os.Open(newFile)
	if err != nil {
		fmt.Printf("Error Opening manifest file: %s/n", err)
		return err
	}

	theBytes := make([]byte, 1000)
	numRead, err := fd.Read(theBytes)
	if err != nil {
		fmt.Printf("Error reading %s: %s\n", newFile, err)
		return err
	}

	if err := json.Unmarshal(theBytes[:numRead], &newMf); err != nil {
		fmt.Printf("Unmarshal error: %s\n", err)
		return err
	}

	// Change the json

	// Rewrite the file
	//if _, err := fd.Write(newMf.CanonicalJSON); err != nil {
	//	fmt.Printf("Error writing to file: %s", err)
	//	return err
	//}

	return nil
}
