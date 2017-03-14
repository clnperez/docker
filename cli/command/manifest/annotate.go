package manifest

import (
	"fmt"

	//"github.com/Sirupsen/logrus"
	"github.com/docker/docker/cli"
	"github.com/docker/docker/cli/command"
	"github.com/spf13/cobra"
)

type annotateOptions struct {
	target      string // the target manifest list name
	image       string // the sub-manifest to annotate within the list
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
		Args:  cli.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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
	// @TODO: Now that create is first (unless you're using a yaml file), this will always look for a locally-stored
	// manifest under the "transaction" (folder) they specified on create. They should match (e.g. don't use docker.io/myrepo:latest,
	// then later just myrepo.
	imgInspect, _, err := getImageData(dockerCli, opts.image, opts.target)
	if err != nil {
		return err
	}

	if len(imgInspect) > 1 {
		return fmt.Errorf("Cannot annotate manifest list. Please pass an image (not list) name")
	}

	mf := imgInspect[0]

	fd, err := getManifestFd(mf.Digest, opts.target)
	if err != nil {
		return err
	}
	defer fd.Close()
	newMf, err := unmarshalIntoManifestInspect(fd)
	if err != nil {
		return err
	}

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

	if err := updateMfFile(newMf, opts.target); err != nil {
		return err
	}

	return nil
}
