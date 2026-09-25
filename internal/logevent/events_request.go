package logevent

// RequestRejected is the terminal line for a request rejected before the pipeline; attr reason (Warn).
var RequestRejected = newEvent("request.rejected")

// RequestResponse is emitted once a response is written (Debug).
var RequestResponse = newEvent("request.response")
