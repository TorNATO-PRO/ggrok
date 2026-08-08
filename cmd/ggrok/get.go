// The get subcommand allows a user such as yourself
// to retrieve a file being proxied on the relay if
// that file exists. Additionally, if for some reason an
// error occurs or the QUIC connection closes unexpectedly,
// you may restart from the last successful download point.
// Integrity of both the object on the client and server is checked
// via sha256 hashes. It is recommended you front ggrok via Caddy or
// something else that serves HTTP/1/2/3.

package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
)

const (
	// defaultDownloadRetries names the default number of times
	// to retry a download in succession until either a try is successful,
	// or we gracefully terminate the program.
	defaultDownloadRetries = 3

	// downloadBufferSize describes the size of the copy buffer to apply
	// to the reader of the buffer.
	downloadCopyBufferSize = 64 * 1024
)

// getConfig is the parsed and validated input to a download.
type getConfig struct {
	// the URL of the resource to get
	url url.URL

	// output is the output file path to place the file at
	output string

	// retries is the number of retries that will be employed
	// to attempt to retrieve a file
	retries int

	// stats give you statistics about how quickly the file was
	// downloaded, among other things
	stats bool
}

// getUsage marks the usage string for the get subcommand.
const getUsage = `ggrok get - download a shared file from a relay server

Usage:
  ggrok get [flags] <url>

Flags:
`

// parseGetFlags parses a list of arguments into a
// getConfig, and fails if there is an error present.
// For a list of supported flags please run the
// `ggrok get` command, I do not plan to keep the documentation
// herein up to date with the latest commands and such.
func parseGetFlags(args []string) (getConfig, error) {
	fs := flag.NewFlagSet("get", flag.ExitOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, getUsage)
	}

	var cfg getConfig
	fs.StringVar(&cfg.output, "o", "", "output file path (default: filename from the share)")
	fs.IntVar(&cfg.retries, "retries", defaultDownloadRetries, "max number of attempts")
	fs.BoolVar(&cfg.stats, "stats", false, "print download timing")
	if err := parseFlags(fs, args); err != nil {
		return getConfig{}, err
	}

	if fs.NArg() != 1 {
		fs.Usage()
		return getConfig{}, fmt.Errorf("exactly one URL is required")
	}

	urlString := fs.Arg(0)

	url, err := url.Parse(urlString)
	if err != nil {
		return getConfig{}, fmt.Errorf("failed to parse the url from the provided URL string")
	}

	cfg.url = *url

	return cfg, cfg.validate()
}

// runGet runs the get command, and allows us to
// retrieve a file being hosted on the relay if such a file exists.
// Additionally, if for some reason an error happens or something
// doesn't work properly, you may restart from the last successful
// point - so that you don't need to redownload everything.
func runGet(args []string) error {
	// retrieve the flags passed by the user
	_, err := parseGetFlags(args)
	if err != nil {
		return err
	}

	// TODO: unimplemented
	return nil
}

// validate validates that a config is indeed a valid config.
func (c getConfig) validate() error {
	if c.retries < 1 {
		return fmt.Errorf("-retries must be at least 1")
	}

	return nil
}
