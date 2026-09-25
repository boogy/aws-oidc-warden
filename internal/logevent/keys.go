package logevent

// JSON key names shared by every event line and the base logger.
const (
	keyEventType         = "eventType"
	keyEventCategory     = "eventCategory"
	keyOutcome           = "outcome"
	keyService           = "service"
	keyVersion           = "version"
	keyAdapter           = "adapter"
	keySchemaVersion     = "schemaVersion"
	keyRequestID         = "requestId"
	keyFrontendRequestID = "frontendRequestId"
	keySourceIP          = "sourceIp"
	keySourceIPFrom      = "sourceIpFrom"
)

const serviceName = "aws-oidc-warden"

// schemaVersion is the log schema version stamped on every line by Setup.
const schemaVersion = 1

// sourceFromFrontend is the platform-attested sourceIpFrom, omitted from lines.
const sourceFromFrontend = "frontend"
