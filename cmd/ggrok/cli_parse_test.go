package main

import "github.com/spf13/cobra"

// parseShareFlags validates command input without starting network services.
func parseShareFlags(args []string) (shareConfig, error) {
	cmd, cfg := newShareCommand()
	cmd.RunE = func(*cobra.Command, []string) error { return nil }
	err := executeCommand(cmd, args)
	return *cfg, err
}

// parseListenFlags validates command input without starting network services.
func parseListenFlags(args []string) (listenConfig, error) {
	cmd, cfg := newListenCommand()
	cmd.RunE = func(*cobra.Command, []string) error { return nil }
	err := executeCommand(cmd, args)
	return *cfg, err
}
