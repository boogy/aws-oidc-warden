package logevent

// JWKSDiscoveryFailure is emitted when OIDC discovery fails to locate a
// JWKS URI (Error).
var JWKSDiscoveryFailure = newEvent("jwks.discovery.failure")

// JWKSFetchFailure is emitted when fetching a JWKS document fails (Error).
var JWKSFetchFailure = newEvent("jwks.fetch.failure")

// JWKSRefetchForced is emitted when a JWKS refetch is forced (Info).
var JWKSRefetchForced = newEvent("jwks.refetch.forced")

// JWKSRefetchRateLimited is emitted when a JWKS refetch is rate-limited
// (Warn).
var JWKSRefetchRateLimited = newEvent("jwks.refetch.rate_limited")

// JWKSPrefetchFailure is emitted when the cold-start JWKS warm prefetch
// fails (Warn).
var JWKSPrefetchFailure = newEvent("jwks.prefetch.failure")

// JWKSALBKeyFailure is emitted when fetching an ALB OIDC public key fails
// (Error).
var JWKSALBKeyFailure = newEvent("jwks.alb_key.failure")
