package logevent

// IdPTokenMinted is emitted when an IdP token is signed; carries jti, never the token (Debug).
var IdPTokenMinted = newEvent("idp.token.minted")

// IdPSignFailure is emitted when signing or self-verification fails (Error).
var IdPSignFailure = newEvent("idp.sign.failure")

// IdPKeyLoaded is emitted when a signing key's public half is loaded (Info).
var IdPKeyLoaded = newEvent("idp.key.loaded")

// IdPKeyLoadFailure is emitted when a signing key cannot be loaded (Error).
var IdPKeyLoadFailure = newEvent("idp.key.load.failure")

// IdPKeyInsecureSource is emitted at boot for a file-backed key (Warn).
var IdPKeyInsecureSource = newEvent("idp.key.insecure_source")

// IdPUnavailable is emitted when an IdP endpoint answers 503 because keys are not loaded (Warn).
var IdPUnavailable = newEvent("idp.unavailable")

// IdPDocumentServed is emitted when discovery or JWKS is served (Debug).
var IdPDocumentServed = newEvent("idp.document.served")

// IdPTokenTooLarge is emitted when a minted token exceeds the STS web-identity token limit (Error).
var IdPTokenTooLarge = newEvent("idp.token.too_large")

// IdPPathNotFound is emitted when an IdP-shaped path matches no configured IdP path (Warn).
var IdPPathNotFound = newEvent("idp.path.not_found")

// IdPPathDisabled is emitted when a discovery/JWKS path is requested while idp.enabled is false (Debug).
var IdPPathDisabled = newEvent("idp.path.disabled")

// IdPExchangeFailure is emitted when the unsigned AssumeRoleWithWebIdentity call is refused (Warn).
var IdPExchangeFailure = newEvent("idp.exchange.failure")

// IdPCredentialsSuccess is emitted when credentials are returned; never carries them (Info).
var IdPCredentialsSuccess = newEvent("idp.credentials.success")
