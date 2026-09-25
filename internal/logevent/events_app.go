package logevent

// AppStart is emitted once startup completes (Info).
var AppStart = newEvent("app.start")

// AppStop is emitted on graceful shutdown (Info).
var AppStop = newEvent("app.stop")

// AppInitFailure is emitted when startup fails; attr component names the dependency (Error).
var AppInitFailure = newEvent("app.init.failure")

// AppResourceCloseFailure is a failed deferred Close(); attr resource (Warn).
var AppResourceCloseFailure = newEvent("app.resource_close.failure")
