package ssh

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"ssm/internal/config"
	"ssm/internal/machinecontract"
)

// ClassifyError is the SSH mechanism adapter to the single machine policy
// classifier.
func ClassifyError(err error, connection config.Connection) *machinecontract.ClassifiedError {
	if err == nil {
		return nil
	}
	failure := machinecontract.ClassifySSH(err, machinecontract.SSHContext{
		Alias: connection.Name,
		Host:  connection.Host,
		Port:  connection.Port,
	})
	return machinecontract.NewClassifiedError(failure)
}

// DialTimeout returns the connect timeout: the total budget for TCP connect
// plus the SSH handshake (including authentication). It reads
// SSM_CONNECT_TIMEOUT (--connect-timeout), then SSM_TIMEOUT (the --timeout
// compatibility alias) and SSM_DIAL_TIMEOUT, else defaults to 15s. Values are
// Go durations ("10s", "1m") or integer seconds.
func DialTimeout() time.Duration {
	for _, key := range []string{"SSM_CONNECT_TIMEOUT", "SSM_TIMEOUT", "SSM_DIAL_TIMEOUT"} {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			if duration, err := parseTimeout(value); err == nil && duration > 0 {
				return duration
			}
		}
	}
	return dialTimeout
}

func parseTimeout(value string) (time.Duration, error) {
	if duration, err := time.ParseDuration(value); err == nil {
		return duration, nil
	}
	if seconds, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second, nil
	}
	return 0, fmt.Errorf("invalid timeout %q", value)
}
