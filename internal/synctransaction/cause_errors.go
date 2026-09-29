package synctransaction

import "ssm/internal/cloud"

// HTTPStatusError and MissingTokenError re-export the typed sync-service
// failures carried in refresh and publication error chains, so policy owners
// classify causes with errors.As without depending on the transport package.
type (
	HTTPStatusError   = cloud.HTTPStatusError
	MissingTokenError = cloud.MissingTokenError
)
