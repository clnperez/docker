package manifest

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Sirupsen/logrus"

	"github.com/docker/docker/cli"
	"github.com/docker/docker/cli/command"
	"github.com/spf13/cobra"
)

// NewInspectCommand creates a new `docker manifest inspect` command
func newInspectCommand(dockerCli *command.DockerCli) *cobra.Command {
	var opts fetchOptions

	cmd := &cobra.Command{
		Use:   "inspect [OPTIONS] NAME[:TAG]",
		Short: "Display an image's manifest.",
		Args:  cli.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.remote = args[0]
			return runListInspect(dockerCli, opts)
		},
	}

	flags := cmd.Flags()

	flags.BoolVarP(&opts.raw, "raw", "r", false, "Provide raw JSON output")
	command.AddTrustedFlags(flags, true)

	return cmd
}

func runListInspect(dockerCli *command.DockerCli, opts fetchOptions) error {

	// Get the data and then format it
	var (
		imgInspect []ImgManifestInspect
	)

	name := opts.remote
	imgInspect, _, err := getImageData(dockerCli, name)
	if err != nil {
		logrus.Fatal(err)
	}
	if opts.raw == true {
		out, err := json.Marshal(imgInspect)
		if err != nil {
			logrus.Fatal(err)
		}
		fmt.Println(string(out))
		return nil
	}

	// Don't overwrite local copies on inspect.
	if err := storeManifest(imgInspect, false); err != nil {
		return err
	}

	// output basic informative details about the image
	if len(imgInspect) == 1 {
		// this is a basic single manifest
		fmt.Printf("%s: manifest type: %s\n", name, imgInspect[0].MediaType)
		fmt.Printf("      Digest: %s\n", imgInspect[0].Digest)
		fmt.Printf("Architecture: %s\n", imgInspect[0].Architecture)
		fmt.Printf("          OS: %s\n", imgInspect[0].Os)
		fmt.Printf("    # Layers: %d\n", len(imgInspect[0].Layers))
		for i, digest := range imgInspect[0].Layers {
			fmt.Printf("      layer %d: digest = %s\n", i+1, digest)
		}
		return nil
	}
	// More than one response. This is a manifest list.
	fmt.Printf("%s is a manifest list containing the following %d manifest references:\n", name, len(imgInspect))
	for i, img := range imgInspect {
		fmt.Printf("%d    Mfst Type: %s\n", i+1, img.MediaType)
		fmt.Printf("%d       Digest: %s\n", i+1, img.Digest)
		fmt.Printf("%d  Mfst Length: %d\n", i+1, img.Size)
		fmt.Printf("%d     Platform:\n", i+1)
		fmt.Printf("%d           -      OS: %s\n", i+1, img.Platform.OS)
		// WINDOWS SUPPORT - NOT VENDORED YET fmt.Printf("%d           - OS Vers: %s\n", i+1, img.Platform.OSVersion)
		// WINDOWS SUPPORT - NOT VENDORED YET fmt.Printf("%d           - OS Feat: %s\n", i+1, img.Platform.OSFeatures)
		fmt.Printf("%d           -    Arch: %s\n", i+1, img.Platform.Architecture)
		fmt.Printf("%d           - Variant: %s\n", i+1, img.Platform.Variant)
		fmt.Printf("%d           - Feature: %s\n", i+1, strings.Join(img.Platform.Features, ","))
		fmt.Printf("%d     # Layers: %d\n", i+1, len(img.Layers))
		for j, digest := range img.Layers {
			fmt.Printf("         layer %d: digest = %s\n", j+1, digest)
		}
		fmt.Println()
	}
	return nil
}
