package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"ssm/internal/syncserver"
)

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:8787", "listen address")
	dataDir := fs.String("data-dir", "/srv/ssm-sync", "sync server data directory")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	srv, err := syncserver.New(*dataDir)
	if err != nil {
		printError(err)
		os.Exit(1)
	}

	httpSrv := &http.Server{
		Addr:              *listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	fmt.Printf("ssm sync server listening on %s\n", *listen)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		printError(err)
		os.Exit(1)
	}
}
