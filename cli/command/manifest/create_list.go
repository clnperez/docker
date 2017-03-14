package manifest

import (
	"fmt"

	"github.com/Sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/docker/distribution/reference"
	"github.com/docker/docker/cli"
	"github.com/docker/docker/cli/command"
	"github.com/docker/docker/registry"
)

type createOpts struct {
	newRef string
}

func newCreateListCommand(dockerCli *command.DockerCli) *cobra.Command {

	opts := createOpts{}

	cmd := &cobra.Command{
		Use:   "create --name newRef manifest [manifest...]",
		Short: "Push a manifest list for an image to a repository",
		Args:  cli.RequiresMinArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return createManifestList(dockerCli, opts, args)
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&opts.newRef, "name", "n", "", "")
	return cmd
}

func createManifestList(dockerCli *command.DockerCli, opts createOpts, manifests []string) error {

	// Just do some basic verification here, and leave the rest for when the user pushes the list
	targetRef, err := reference.ParseNormalizedNamed(opts.newRef)
	if err != nil {
		return fmt.Errorf("Error parsing name for manifest list (%s): %v", opts.newRef, err)
	}
	_, err = registry.ParseRepositoryInfo(targetRef)
	if err != nil {
		return fmt.Errorf("Error parsing repository name for manifest list (%s): %v", opts.newRef, err)
	}

	transactionID, err := refToFilename(opts.newRef)
	if err != nil {
		return fmt.Errorf("Error creating manifest list transaction: %s", err)
	}

	// Now create the local manifest list transaction by looking up the manifest schemas
	// for the constituent images:
	logrus.Info("Retrieving digests of images...")
	for _, manifestRef := range manifests {

		// This will store the canditate images' manifests locally
		mfstData, _, err := getImageData(dockerCli, manifestRef, transactionID)
		if err != nil {
			return err
		}

		if len(mfstData) > 1 {
			// too many responses--can only happen if a manifest list was returned for the name lookup
			return fmt.Errorf("You specified a manifest list entry from a digest that points to a current manifest list. Manifest lists do not allow recursion.")
		}

	}
	return nil
}
