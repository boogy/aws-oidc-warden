package types

// OpaqueClaim is a claim whose original JSON type was destroyed by an upstream
// stringifier (the API Gateway HTTP API JWT Authorizer's map[string]string
// context). Readable as text, but undecidable under negation.
type OpaqueClaim string
