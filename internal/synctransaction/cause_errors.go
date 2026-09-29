package synctransaction

import "ssm/internal/cloud"

// HTTPStatusError, MissingTokenError and TransportError re-export the typed
// sync-service failures carried in refresh and publication error chains, so
// policy owners classify causes with errors.As without depending on the
// transport package.
type (
	HTTPStatusError   = cloud.HTTPStatusError
	MissingTokenError = cloud.MissingTokenError
	TransportError    = cloud.TransportError
)

// IsTLSFailure reports whether err is a TLS or certificate failure.
func IsTLSFailure(err error) bool { return cloud.IsTLSFailure(err) }
