package logevent

// AuthzDecision is the pipeline's terminal line; outcome allow (Info) or deny (Warn).
var AuthzDecision = newEvent("authz.decision")

// AuthzStageDeny is emitted by the pipeline stage that denies a request; attr stage names it (Debug).
var AuthzStageDeny = newEvent("authz.stage.deny")

// AuthzTagAuthSuccess is emitted when tag-based authorization succeeds (Info).
var AuthzTagAuthSuccess = newEvent("authz.tag_auth.success")

// AuthzSessionNameIgnored is emitted when a requested sessionName is dropped for a mapping or default name (Warn).
var AuthzSessionNameIgnored = newEvent("authz.session_name.ignored")

// AuthzTagAuthLookupFailure is emitted when a tag-auth lookup fails (Warn).
var AuthzTagAuthLookupFailure = newEvent("authz.tag_auth.lookup_failure")
