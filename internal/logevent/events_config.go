package logevent

// ConfigReloadSuccess is emitted when a remote config reload succeeds (Info).
var ConfigReloadSuccess = newEvent("config.reload.success")

// ConfigReloadFailure is emitted when a remote config reload fails (Error).
var ConfigReloadFailure = newEvent("config.reload.failure")

// ConfigHotReloadEnabled is emitted once hot-reload is armed at startup
// (Info).
var ConfigHotReloadEnabled = newEvent("config.hot_reload.enabled")

// ConfigFragmentsMerged is emitted when config fragments are merged into the
// base config (Info).
var ConfigFragmentsMerged = newEvent("config.fragments.merged")

// ConfigFragmentsSoftCap is emitted when the fragment count hits its soft
// cap (Warn).
var ConfigFragmentsSoftCap = newEvent("config.fragments.soft_cap")

// ConfigEnvInvalid is emitted when an environment variable override fails to
// parse (Warn).
var ConfigEnvInvalid = newEvent("config.env.invalid")

// ConfigWarning is emitted for a Validate() warning; attr warning carries its
// stable snake_case code (Warn).
var ConfigWarning = newEvent("config.warning")

// ConfigJWTValidationDelegated is emitted when jwt_validation.mode delegates
// token verification upstream (Warn).
var ConfigJWTValidationDelegated = newEvent("config.jwt_validation.delegated")
