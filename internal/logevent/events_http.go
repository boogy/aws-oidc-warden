package logevent

// HTTPServerStart is emitted when the local HTTP server starts listening
// (Info). Local server only.
var HTTPServerStart = newEvent("http.server.start")

// HTTPServerFailure is emitted when the local HTTP server fails to serve
// (Error). Local server only.
var HTTPServerFailure = newEvent("http.server.failure")

// HTTPResponseFailure is emitted when the local server fails to handle a request (Error).
var HTTPResponseFailure = newEvent("http.response.failure")

// HTTPWriteFailure is emitted when the local server fails to read or write a body, usually a client disconnect (Warn).
var HTTPWriteFailure = newEvent("http.response.write_failure")
