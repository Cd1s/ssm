//go:build !linux && !darwin

package main

func pushPersistenceFailureSupported() bool {
	return false
}

func injectPushPersistenceFailureFromEnvironment() {}
