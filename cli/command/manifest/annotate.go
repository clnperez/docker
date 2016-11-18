package manifest

import (
	"fmt"

	//"github.com/Sirupsen/logrus"
	"github.com/docker/docker/cli"
	"github.com/docker/docker/cli/command"
	"github.com/spf13/cobra"
)

type annotateOptions struct {
	remote      string
	variant     string
	cpuFeatures []string
	osFeatures  []string
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
	flags.StringSliceVarP(&opts.cpuFeatures, "cpuFeatures", "c", []string{}, "Add feature metadata to a manifest before pushing it.")
	// @TODO: Maybe no shorthand? These are bad =D
	flags.StringSliceVarP(&opts.osFeatures, "osFeatures", "o", []string{}, "Add feature metadata to a manifest before pushing it.")
	flags.StringVarP(&opts.variant, "variant", "v", "", "Add arch variant to a manifest before pushing it.")

	command.AddTrustedFlags(flags, true)

	return cmd
}

func runManifestAnnotate(dockerCli *command.DockerCli, opts annotateOptions) error {

	// Make sure the manifests are pulled, find the file you need, unmarshal the json, edit the file, and done.
	imgInspect, _, err := getImageData(dockerCli, opts.remote, false)
	if err != nil {
		return err
	}

	if len(imgInspect) != 1 {
		return fmt.Errorf("Cannot annotate manifest list. Please pass an image name")
	}

	mf := imgInspect[0]

	fd, err := getManifestFd(mf.Digest)
	if err != nil {
		fmt.Printf("Error getting mf fd: %s", err)
		return err
	}
	defer fd.Close()
	newMf, err := unmarshalIntoManifestInspect(fd)
	if err != nil {
		fmt.Printf("Error unmarshaling mf from fd: %s", err)
		return err
	}

	// Update the mf
	// @TODO: Verification? Move the one from create to here?
	if len(opts.cpuFeatures) > 0 {
		newMf.Platform.Features = append(mf.Platform.Features, opts.cpuFeatures...)
	}
	if len(opts.osFeatures) > 0 {
		newMf.Platform.OSFeatures = append(mf.Platform.OSFeatures, opts.osFeatures...)
	}
	if opts.variant != "" {
		newMf.Platform.Variant = opts.variant
	}

	if err := updateMfFile(newMf); err != nil {
		return err
	}

	return nil
}
