// Command ggrok forwards local TCP ports through an mTLS relay.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var errUsage = errors.New("invalid arguments")

const exitUsageError = 2

// newCommand keeps parsing errors separate from runtime failures. Each
// constructor owns its options, so building help never reads config files.
func newCommand(use, short string) *cobra.Command {
	cmd := &cobra.Command{
		Use: use, Short: short, Args: cobra.NoArgs,
		SilenceUsage: true, SilenceErrors: true,
	}
	cmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return fmt.Errorf("%w: %w", errUsage, err)
	})
	return cmd
}

func showCommandHelp(cmd *cobra.Command, _ []string) error { return cmd.Help() }

func newRootCommand() *cobra.Command {
	root := newCommand("ggrok", "Forward local TCP ports through a relay you run yourself")
	// Let Cobra diagnose unknown subcommands and suggest close matches.
	root.Args = nil
	root.Long = root.Short + ".\n\nConnection settings use flags, GGROK_* environment variables, then ~/.ggrok/config.json.\nLegacy single-dash long flags are also accepted."
	root.SetOut(os.Stdout)
	root.SetErr(os.Stderr)
	registerColorFlag(root.PersistentFlags(), &colorFlag)
	share, _ := newShareCommand()
	listen, _ := newListenCommand()
	relay, _ := newRelayCommand()
	ca := newCommand("ca", "Manage the private certificate authority")
	ca.RunE = showCommandHelp
	ca.AddCommand(newCAInitCommand(), newCAIssueCommand(), newCAListCommand(), newCARevokeCommand(), newCACRLCommand())
	admin := newCommand("admin", "Inspect and manage a running relay")
	admin.RunE = showCommandHelp
	admin.Long = admin.Short + ".\n\nRequires a certificate issued with ggrok ca issue --admin and a relay started with --admin."
	admin.AddCommand(newAdminListCommand(), newAdminKickCommand(), newAdminReloadCRLCommand())
	root.AddCommand(share, listen, relay, ca, admin)
	return root
}

// normalizeLegacyFlags accepts the documented Go-style -long flags alongside
// GNU-style --long flags. Walk the command tree and skip flag values: a value
// such as "-server" must never be rewritten, nor anything following "--".
func normalizeLegacyFlags(cmd *cobra.Command, args []string) []string {
	result := append([]string(nil), args...)
	for i := 0; i < len(result); i++ {
		arg := result[i]
		if arg == "--" {
			break
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			var consumesValue bool
			result[i], consumesValue = normalizeLegacyFlag(cmd, arg)
			if consumesValue {
				i++
			}
			continue
		}
		for _, child := range cmd.Commands() {
			if child.Name() == arg {
				cmd = child
				break
			}
		}
	}
	return result
}

// normalizeLegacyFlag reports whether the following word is a flag value.
func normalizeLegacyFlag(cmd *cobra.Command, arg string) (string, bool) {
	name, _, attached := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(arg, "-"), "-"), "=")
	if name == "help" && strings.HasPrefix(arg, "-help") {
		return "-" + arg, false
	}
	f := lookupFlag(cmd, name)
	if f == nil {
		return arg, false
	}
	if !strings.HasPrefix(arg, "--") && len(name) > 1 {
		arg = "-" + arg
	}
	return arg, !attached && f.NoOptDefVal == ""
}

func lookupFlag(cmd *cobra.Command, name string) *pflag.Flag {
	for current := cmd; current != nil; current = current.Parent() {
		if f := current.Flags().Lookup(name); f != nil {
			return f
		}
		if f := current.PersistentFlags().Lookup(name); f != nil {
			return f
		}
	}
	return nil
}

func executeCommand(cmd *cobra.Command, args []string) error {
	cmd.SetArgs(normalizeLegacyFlags(cmd, args))
	return cmd.Execute()
}

func run(args []string) error {
	colorFlag = colorModeFromEnv()
	return executeCommand(newRootCommand(), args)
}

func main() {
	err := run(os.Args[1:])
	if err == nil || errors.Is(err, context.Canceled) {
		return
	}
	fmt.Fprintf(os.Stderr, "%s %s\n", stderrColors().red("ggrok:"), terminalText(err.Error()))
	if errors.Is(err, errUsage) {
		os.Exit(exitUsageError)
	}
	os.Exit(1)
}
