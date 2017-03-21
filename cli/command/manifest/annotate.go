package manifest

import (
	"fmt"

	"github.com/Sirupsen/logrus"
	"github.com/docker/distribution/reference"
	"github.com/docker/docker/cli"
	"github.com/docker/docker/cli/command"
	"github.com/spf13/cobra"
)

type annotateOptions struct {
	target      string // the target manifest list name (also transaction ID)
	image       string // the manifest to annotate within the list
	variant     string // an architecture variant
	os          string
	arch        string
	cpuFeatures []string
	osFeatures  []string
}

// NewAnnotateCommand creates a new `docker manifest annotate` command
func newAnnotateCommand(dockerCli *command.DockerCli) *cobra.Command {
	var opts annotateOptions

	cmd := &cobra.Command{
		Use:   "annotate NAME[:TAG] [OPTIONS]",
		Short: "Add additional information to an image's manifest.",
		Args:  cli.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			// @TODO: These seem backwards. Am I using this incorrectly?
			opts.target = args[0]
			opts.image = args[1]
			return runManifestAnnotate(dockerCli, opts)
		},
	}

	flags := cmd.Flags()

	// @TODO: Should we do any validation? We can't have an exhaustive list
	flags.StringVar(&opts.os, "os", "", "Add ios info to a manifest before pushing it.")
	flags.StringVar(&opts.arch, "arch", "", "Add arch info to a manifest before pushing it.")
	flags.StringSliceVar(&opts.cpuFeatures, "cpuFeatures", []string{}, "Add feature info to a manifest before pushing it.")
	flags.StringSliceVar(&opts.osFeatures, "osFeatures", []string{}, "Add feature info to a manifest before pushing it.")
	flags.StringVar(&opts.variant, "variant", "", "Add arch variant to a manifest before pushing it.")

	return cmd
}

func runManifestAnnotate(dockerCli *command.DockerCli, opts annotateOptions) error {

	// Make sure the manifests are pulled, find the file you need, unmarshal the json, edit the file, and done.

	// @TODO: Should we be able to annotate a digest? like `docker pull ubuntu@sha256:45b2...`
	targetRef, err := reference.ParseNormalizedNamed(opts.target)
	if err != nil {
		return fmt.Errorf("Annotate: Error parsing name for manifest list (%s): %s", opts.target, err)
	}
	imgRef, err := reference.ParseNormalizedNamed(opts.image)
	if err != nil {
		return fmt.Errorf("Annotate: Error prasing name for manifest (%s): %s:", opts.image, err)
	}

	transactionID := makeFilesafeName(targetRef.Name())
	logrus.Debugf("Beginning annotate for %s/%s", opts.image, transactionID)

	imgInspect, _, err := getImageData(dockerCli, opts.image, transactionID, false)
	if err != nil {
		return err
	}

	if len(imgInspect) > 1 {
		return fmt.Errorf("Cannot annotate manifest list. Please pass an image (not list) name")
	}

	mf := imgInspect[0]
	logrus.Debugf("Retreived image to annotate")

	fd, err := getManifestFd(makeFilesafeName(imgRef.String()), transactionID)
	if err != nil {
		return err
	}
	defer fd.Close()
	newMf, err := unmarshalIntoManifestInspect(fd)
	if err != nil {
		return err
	}

	logrus.Debugf("Annotating %s", imgRef.String())

	// Update the mf
	// @TODO: Prevent duplicates
	// validate os/arch input
	/*if opts.arch == "" || opts.os == "" {
		return fmt.Errorf("You must specify an arch and os.")
	}
	if !isValidOSArch(opts.os, opts.arch) {
		return fmt.Errorf("Manifest entry for image %s has unsupported os/arch combination: %s/%s", opts.remote, opts.os, opts.arch)
	}*/
	if opts.os != "" {
		newMf.Os = opts.os
		newMf.Platform.OS = opts.os
	}
	if opts.arch != "" {
		newMf.Architecture = opts.arch
		newMf.Platform.Architecture = opts.arch
	}
	if len(opts.cpuFeatures) > 0 {
		newMf.Platform.Features = append(mf.Platform.Features, opts.cpuFeatures...)
	}
	if len(opts.osFeatures) > 0 {
		newMf.Platform.OSFeatures = append(mf.Platform.OSFeatures, opts.osFeatures...)
	}
	if opts.variant != "" {
		newMf.Platform.Variant = opts.variant
	}
	// @TODO: Recalculate the digest here

	if err := updateMfFile(newMf, makeFilesafeName(imgRef.String()), makeFilesafeName(targetRef.Name())); err != nil {
		return err
	}

	return nil
}
