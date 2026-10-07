package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"ssm/internal/machinecontract"
	"ssm/internal/ssh"
)

func runTunnelArgs(args []string) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.TunnelInvalidArguments, machinecontract.Details{Message: "tunnel requires an exact host alias"}))
	}
	alias := args[0]
	var specs []ssh.TunnelSpec
	opts := ssh.TunnelOptions{}
	for i := 1; i < len(args); i++ {
		arg := args[i]
		require := func() string {
			if i+1 >= len(args) {
				os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.TunnelInvalidArguments, machinecontract.Details{Message: arg + " requires a value"}))
			}
			i++
			return args[i]
		}
		switch arg {
		case "-L":
			value := require()
			spec, err := parseTunnelLocalForward(value)
			if err != nil {
				os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.TunnelInvalidArguments, machinecontract.Details{Cause: err}))
			}
			specs = append(specs, spec)
		case "-D":
			value := require()
			spec, err := parseTunnelDynamicForward(value)
			if err != nil {
				os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.TunnelInvalidArguments, machinecontract.Details{Cause: err}))
			}
			specs = append(specs, spec)
		case "--connect-timeout":
			d, err := time.ParseDuration(require())
			if err != nil || d <= 0 {
				os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.TunnelInvalidArguments, machinecontract.Details{Message: "invalid --connect-timeout"}))
			}
			opts.ConnectTimeout = d
		case "--duration":
			d, err := time.ParseDuration(require())
			if err != nil || d <= 0 {
				os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.TunnelInvalidArguments, machinecontract.Details{Message: "invalid --duration"}))
			}
			opts.Duration = d
		case "--ready-file":
			opts.ReadyFile = require()
		case "--allow-remote-bind":
			opts.AllowRemoteBind = true
		case "--yes":
			opts.Yes = true
		case "--json":
			machineJSON = true
		default:
			os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.TunnelInvalidArguments, machinecontract.Details{Message: fmt.Sprintf("unknown tunnel option %q", arg)}))
		}
	}
	if len(specs) == 0 {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.TunnelInvalidArguments, machinecontract.Details{Message: "tunnel requires at least one -L or -D"}))
	}
	if err := ssh.ValidateTunnelSpecs(specs, opts); err != nil {
		failure, ok := machinecontract.FailureFromError(err)
		if !ok {
			failure = machinecontract.Classify(machinecontract.TunnelInvalidArguments, machinecontract.Details{Cause: err})
		}
		os.Exit(machinecontract.WriteFailure(machineJSON, failure, failure))
	}
	unlock()
	if opts.ConnectTimeout > 0 {
		old, had := os.LookupEnv("SSM_CONNECT_TIMEOUT")
		_ = os.Setenv("SSM_CONNECT_TIMEOUT", opts.ConnectTimeout.String())
		defer func() {
			if had {
				_ = os.Setenv("SSM_CONNECT_TIMEOUT", old)
			} else {
				_ = os.Unsetenv("SSM_CONNECT_TIMEOUT")
			}
		}()
	}
	if _, err := syncTransaction(false).Refresh(); err != nil {
		failure := machinecontract.ClassifySyncFailure(err, machinecontract.SyncPullFailed)
		os.Exit(machinecontract.WriteFailure(machineJSON, failure, failure))
	}
	v, err := loadVault()
	if err != nil {
		os.Exit(machinecontract.WriteClassified(machineJSON, machinecontract.GenericFailure, machinecontract.Details{Cause: err}))
	}
	c, _, ok := resolveConnection(v, alias)
	if !ok {
		connectionNotFound(alias, v)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	opts.OnReady = func(result ssh.TunnelResult) error {
		if machineJSON {
			return writeMachineValueErr(struct {
				OK        bool                 `json:"ok"`
				Alias     string               `json:"alias"`
				Listeners []ssh.TunnelListener `json:"listeners"`
			}{true, alias, result.Listeners})
		}
		for _, listener := range result.Listeners {
			if listener.Target == "" {
				fmt.Printf("listen=%s\n", listener.Bind)
			} else {
				fmt.Printf("listen=%s target=%s\n", listener.Bind, listener.Target)
			}
		}
		return nil
	}
	result, runErr := ssh.RunTunnel(ctx, c, v, specs, opts)
	if runErr != nil {
		failure, ok := machinecontract.FailureFromError(runErr)
		if !ok {
			failure = machinecontract.Classify(machinecontract.ConnectionLost, machinecontract.Details{Cause: runErr, Alias: alias})
		}
		os.Exit(machinecontract.WriteFailure(machineJSON, failure, failure))
	}
	if machineJSON {
		_ = writeMachineValueErr(struct {
			OK     bool   `json:"ok"`
			Event  string `json:"event"`
			Reason string `json:"reason"`
		}{true, "closed", result.Reason})
	} else {
		fmt.Printf("closed=1 reason=%s\n", result.Reason)
	}
}

func parseTunnelLocalForward(value string) (ssh.TunnelSpec, error) {
	if strings.Contains(value, ":0:") {
		if spec, err := ssh.ParseLocalForward(strings.Replace(value, ":0:", ":1:", 1)); err == nil {
			spec.Port = 0
			return spec, nil
		}
	}
	return ssh.ParseLocalForward(value)
}

func parseTunnelDynamicForward(value string) (ssh.TunnelSpec, error) {
	if strings.HasSuffix(value, ":0") || value == "0" {
		replaced := strings.TrimSuffix(value, ":0")
		if value == "0" {
			replaced = "1"
		} else {
			replaced += ":1"
		}
		if spec, err := ssh.ParseDynamicForward(replaced); err == nil {
			spec.Port = 0
			return spec, nil
		}
	}
	return ssh.ParseDynamicForward(value)
}

func writeMachineValueErr(value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = fmt.Println(string(data))
	return err
}
