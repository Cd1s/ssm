package update

import "errors"

type recoveryRequiredError struct {
	cause error
}

type recoveryBlockedError struct {
	cause error
}

type canonicalPreservedError struct {
	cause error
}

func (err *recoveryRequiredError) Error() string {
	return err.cause.Error()
}

func (err *recoveryRequiredError) Unwrap() error {
	return err.cause
}

func (err *recoveryBlockedError) Error() string {
	return err.cause.Error()
}

func (err *recoveryBlockedError) Unwrap() error {
	return err.cause
}

func (err *canonicalPreservedError) Error() string {
	return err.cause.Error()
}

func (err *canonicalPreservedError) Unwrap() error {
	return err.cause
}

func requireRecovery(cause error) error {
	if cause == nil {
		return nil
	}
	return &recoveryRequiredError{cause: cause}
}

func blockOnRecoveryEvidence(cause error) error {
	if cause == nil || IsRecoveryRequired(cause) || isCanonicalPreserved(cause) {
		return cause
	}
	return &recoveryBlockedError{cause: cause}
}

func preserveCanonical(cause error) error {
	if cause == nil {
		return nil
	}
	return &canonicalPreservedError{cause: cause}
}

// IsRecoveryRequired reports whether a Windows replacement moved the original
// executable from its canonical path but could not complete authenticated
// restoration and prepared-state clearance. Callers must block command dispatch
// and later updates until a subsequent authenticated recovery succeeds.
func IsRecoveryRequired(err error) bool {
	var recoveryErr *recoveryRequiredError
	return errors.As(err, &recoveryErr)
}

// IsRecoveryBlocked reports that Windows recovery evidence refused cleanup or
// authentication without proving the original executable is canonical. It is
// not the authenticated recovery-required terminal state and must not inherit
// the ordinary update-preservation promise.
func IsRecoveryBlocked(err error) bool {
	var blockedErr *recoveryBlockedError
	return errors.As(err, &blockedErr)
}

func isCanonicalPreserved(err error) bool {
	var preservedErr *canonicalPreservedError
	return errors.As(err, &preservedErr)
}
