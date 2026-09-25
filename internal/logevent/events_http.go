package logevent

// HTTPServerStart is emitted when the local HTTP server starts listening
// (Info). Local server only.
var HTTPServerStart = newEvent("http.server.start")

// HTTPServerFailure is emitted when the local HTTP server fails to serve
// (Error). Local server only.
var HTTPServerFailure = newEvent("http.server.failure")

// HTTPResponseFailure is emitted when writing a local HTTP response fails
// (Error). Local server only.
var HTTPResponseFailure = newEvent("http.response.failure")
