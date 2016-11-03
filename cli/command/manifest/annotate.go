package manifest

import (
	//"encoding/json"
	"fmt"

	/*
		"github.com/Sirupsen/logrus"
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
	for _, flag := range opts.features {
		fmt.Printf("Feature flags:%s \n", flag)
	}
	for _, flag := range opts.variants {
		fmt.Printf("Variant flags:%s \n", flag)
	}

	return nil
}
