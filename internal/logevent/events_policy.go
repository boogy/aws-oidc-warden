package logevent

// PolicySessionLoaded is emitted when a session policy is loaded; attr
// source identifies where from: "s3" or "inline" (Debug).
var PolicySessionLoaded = newEvent("policy.session.loaded")

// PolicySessionLoadFailure is emitted when loading a session policy fails
// (Error).
var PolicySessionLoadFailure = newEvent("policy.session.load.failure")

// PolicyS3OwnerUnpinned is emitted once at startup when session_policy_bucket is set without session_policy_bucket_owner (Warn).
var PolicyS3OwnerUnpinned = newEvent("policy.s3_owner_unpinned")
