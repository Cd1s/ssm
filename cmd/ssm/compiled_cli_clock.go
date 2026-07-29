//go:build compiled_cli_contract

package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func syncTransactionClock() func() time.Time {
	endpoint := os.Getenv("SSM_COMPILED_TEST_CLOCK_URL")
	if endpoint == "" {
		return nil
	}
	client := &http.Client{Timeout: 5 * time.Second}
	return func() time.Time {
		response, err := client.Get(endpoint) //nolint:gosec,noctx // test-tagged loopback fixture endpoint with a bounded client
		if err != nil {
			panic(fmt.Sprintf("read compiled test clock: %v", err))
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			panic(fmt.Sprintf("read compiled test clock: status %d", response.StatusCode))
		}
		data, err := io.ReadAll(io.LimitReader(response.Body, 64))
		if err != nil {
			panic(fmt.Sprintf("read compiled test clock response: %v", err))
		}
		nanoseconds, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		if err != nil {
			panic(fmt.Sprintf("decode compiled test clock: %v", err))
		}
		return time.Unix(0, nanoseconds).UTC()
	}
}
