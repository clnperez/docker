package image

import (
	"fmt"
	"strings"

	"github.com/docker/distribution/reference"
	"github.com/docker/docker/cli"
	"github.com/docker/docker/cli/command"
	"github.com/docker/docker/registry"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
)

type pullOptions struct {
	remote string
	all    bool
}

// NewPullCommand creates a new `docker pull` command
func NewPullCommand(dockerCli command.Cli) *cobra.Command {
	var opts pullOptions

	cmd := &cobra.Command{
		Use:   "pull [OPTIONS] NAME[:TAG|@DIGEST]",
		Short: "Pull an image or a repository from a registry",
		Args:  cli.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.remote = args[0]
			return runPull(dockerCli, opts)
		},
	}

	flags := cmd.Flags()

	flags.BoolVarP(&opts.all, "all-tags", "a", false, "Download all tagged images in the repository")
	command.AddTrustVerificationFlags(flags)

	return cmd
}

func runPull(dockerCli command.Cli, opts pullOptions) error {
	distributionRef, err := reference.ParseNormalizedNamed(opts.remote)
	fmt.Println("distributionRef is : ", distributionRef)
	if err != nil {
		return err
	}
	// looks to see if it's going to pull all, and if the distribution ref doesn't just
	// contain a repo name
	fmt.Println("all of the opts are: ", opts.all)
	if opts.all && !reference.IsNameOnly(distributionRef) {
		return errors.New("tag can't be used with --all-tags/-a")
	}
	// looks to see if it's not going to pull all, and it only contains a repo name
	if !opts.all && reference.IsNameOnly(distributionRef) {
		distributionRef = reference.TagNameOnly(distributionRef)
		if tagged, ok := distributionRef.(reference.Tagged); ok {
			fmt.Fprintf(dockerCli.Out(), "Using default tag: %s\n", tagged.Tag())
		}
	}

	// Resolve the Repository name from fqn to RepositoryInfo
	repoInfo, err := registry.ParseRepositoryInfo(distributionRef)
	fmt.Println("repo info is : ", repoInfo)
	if err != nil {
		return err
	}

	ctx := context.Background()
	fmt.Println("ctx here is : ", ctx)
	authConfig := command.ResolveAuthConfig(ctx, dockerCli, repoInfo.Index)
	fmt.Println("auth config is : ", authConfig)
	requestPrivilege := command.RegistryAuthenticationPrivilegedFunc(dockerCli, repoInfo.Index, "pull")

	// Check if reference has a digest
	_, isCanonical := distributionRef.(reference.Canonical)
	if command.IsTrusted() && !isCanonical {
		err = trustedPull(ctx, dockerCli, repoInfo, distributionRef, authConfig, requestPrivilege)
	} else {
		err = imagePullPrivileged(ctx, dockerCli, authConfig, reference.FamiliarString(distributionRef), requestPrivilege, opts.all)
	}
	if err != nil {
		if strings.Contains(err.Error(), "when fetching 'plugin'") {
			return errors.New(err.Error() + " - Use `docker plugin install`")
		}
		return err
	}

	return nil
}
