package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"ssm/internal/machinecontract"
	"ssm/internal/syncserver"
)

func runServer(args []string) {
	var flagOutput bytes.Buffer
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.SetOutput(&flagOutput)
	listen := fs.String("listen", "127.0.0.1:8787", "listen address")
	dataDir := fs.String("data-dir", "/srv/ssm-sync", "sync server data directory")
	if err := fs.Parse(args); err != nil {
		message := flagOutput.String()
		if message == "" {
			message = err.Error() + "\n"
		}
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(machinecontract.WriteFlagHelp(message))
		}
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.InvalidSSHCTLArguments, machinecontract.Details{
			Message: message, Cause: err, Tool: "raw_flag_error",
		}))
	}

	srv, err := syncserver.New(*dataDir)
	if err != nil {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
	}

	httpSrv := &http.Server{
		Addr:              *listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	fmt.Printf("ssm sync server listening on %s\n", *listen)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
	}
}
