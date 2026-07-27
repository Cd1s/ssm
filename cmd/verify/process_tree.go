package main

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
)

func runOwnedCommand(ctx context.Context, command *exec.Cmd) (returnErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	tree, err := newOwnedProcessTree(command)
	if err != nil {
		return err
	}
	defer func() {
		returnErr = errors.Join(returnErr, tree.close())
	}()
	if err := command.Start(); err != nil {
		return err
	}
	if err := tree.attach(command); err != nil {
		killErr := command.Process.Kill()
		waitErr := command.Wait()
		return errors.Join(err, killErr, waitErr)
	}

	waited := make(chan error, 1)
	go func() {
		waited <- command.Wait()
	}()

	select {
	case waitErr := <-waited:
		cleanupErr := tree.terminateAndWait()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return errors.Join(ctxErr, waitErr, cleanupErr)
		}
		return errors.Join(waitErr, cleanupErr)
	case <-ctx.Done():
		terminateErr := tree.terminate()
		if terminateErr != nil {
			terminateErr = errors.Join(terminateErr, command.Process.Kill())
		}
		waitErr := <-waited
		descendantErr := tree.wait()
		return errors.Join(ctx.Err(), terminateErr, waitErr, descendantErr)
	}
}

func ownedCommandOutput(ctx context.Context, command *exec.Cmd) ([]byte, error) {
	var stdout bytes.Buffer
	command.Stdout = &stdout
	err := runOwnedCommand(ctx, command)
	return stdout.Bytes(), err
}

func ownedCommandCombinedOutput(ctx context.Context, command *exec.Cmd) ([]byte, error) {
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	err := runOwnedCommand(ctx, command)
	return output.Bytes(), err
}
