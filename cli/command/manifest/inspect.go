package manifest

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/Sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/docker/distribution/reference"
	"github.com/docker/docker/cli"
	"github.com/docker/docker/cli/command"
)

type inspectOptions struct {
	remote string
	raw    bool
}

// NewInspectCommand creates a new `docker manifest inspect` command
func newInspectCommand(dockerCli *command.DockerCli) *cobra.Command {
	var opts inspectOptions

	cmd := &cobra.Command{
		Use:   "inspect [OPTIONS] NAME[:TAG]",
		Short: "Display an image's manifest, or a remote manifest list.",
		Args:  cli.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.remote = args[0]
			return runListInspect(dockerCli, opts)
		},
	}

	flags := cmd.Flags()

	flags.BoolVarP(&opts.raw, "raw", "r", false, "Provide raw JSON output")

	return cmd
}

func runListInspect(dockerCli *command.DockerCli, opts inspectOptions) error {

	// Get the data and then format it
	var (
		imgInspect []ImgManifestInspect
		prettyJSON bytes.Buffer
	)

	named, err := reference.ParseNormalizedNamed(opts.remote)
	if err != nil {
		return err
	}
	// For now, always pull as there' no reason to store an inspect. They're quick to get.
	// When the engine is multi-arch image aware, we can store these in a universal location to
	// save a little bandwidth.
	imgInspect, _, err = getImageData(dockerCli, named.Name(), "", true)
	if err != nil {
		logrus.Fatal(err)
	}
	// output basic informative details about the image
	if len(imgInspect) == 1 {
		// this is a basic single manifest
		img := imgInspect[0]
		err = json.Indent(&prettyJSON, img.CanonicalJSON, "", "\t")
		if err != nil {
			logrus.Fatal(err)
		}
		fmt.Fprintf(dockerCli.Out(), string(prettyJSON.String()))

		return nil
	}

	// More than one response. This is a manifest list.
	for _, img := range imgInspect {
		err = json.Indent(&prettyJSON, img.CanonicalJSON, "", "\t")
		if err != nil {
			logrus.Fatal(err)
		}
		fmt.Fprintf(dockerCli.Out(), string(prettyJSON.String()))
	}
	return nil
}
