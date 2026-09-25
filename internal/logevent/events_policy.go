package logevent

// PolicySessionLoaded is emitted when a session policy is loaded; attr
// source identifies where from: "s3" or "inline" (Debug).
var PolicySessionLoaded = newEvent("policy.session.loaded")

// PolicySessionLoadFailure is emitted when loading a session policy fails
// (Error).
var PolicySessionLoadFailure = newEvent("policy.session.load.failure")
