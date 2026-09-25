package logevent

// TokenExtract is emitted when a token is extracted from the request (Debug).
var TokenExtract = newEvent("token.extract")

// TokenValidated is emitted once a token passes verification (Debug).
var TokenValidated = newEvent("token.validated")

// TokenClaims is emitted with the token's parsed claims (Debug).
var TokenClaims = newEvent("token.claims")
