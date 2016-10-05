package manifest

import (
	//"errors"
	"fmt"

	"github.com/docker/docker/cli"
	"github.com/docker/docker/cli/command"
	"github.com/spf13/cobra"
)

// NewManifestCommand returns a cobra command for `manifest` subcommands
func NewManifestCommand(dockerCli *command.DockerCli) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "manifest COMMAND",
		Short: "Manage Docker image manifests and lists",
		Long:  manifestListDescription,
		Args:  cli.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(dockerCli.Err(), "\n"+cmd.UsageString())
		},
	}
	// Structure as:
	// manifest fetch <ref>
	// which will fetch either a list, or an image manifest if there is no list?
	// what does the api get?
	cmd.AddCommand(
		//newCreateCommand(dockerCli),
		newListFetchCommand(dockerCli),
		//newInspectCommand(dockerCli),
		//newListCommand(dockerCli),
		//newRemoveCommand(dockerCli),
	)
	return cmd
}

var manifestListDescription = `
The **docker manifest** command has subcommands for managing image manifests and 
manifest lists. A manifest list allows you to use one name to refer to the same image 
build for multiple architectures.

To see help for a subcommand, use:

    docker manifest CMD help

For full details on using docker manifest lists view the registry v2 specification.

`
