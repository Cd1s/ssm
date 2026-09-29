//go:build !unix && !windows

package main

import "errors"

var errBackgroundUnsupported = errors.New("background sync is unsupported on this platform")

func startDetachedBackgroundSync(string, string) error {
	return errBackgroundUnsupported
}
