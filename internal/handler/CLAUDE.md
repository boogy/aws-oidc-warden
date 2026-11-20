# Handler

Extends [../../CLAUDE.md](../../CLAUDE.md). Request pipeline shared by every deployment.

This file is a map plus the rules code cannot state. Read `processor.go` top to bottom before changing the flow; `docs/ARCHITECTURE.md` has the diagrams.

## Where things are

- `bootstrap.go` — `NewBootstrap(adapter)`: DI, extractor selection, cold-start warm-ups.
- `processor.go` — `ProcessRequest`: refresh → extract → stale gate → account guard → `AuthorizeRoles` → tag-auth (only if `cfg.TagAuthMayGrant(role)`) → policy/tags → assume → audit.
- `idp.go`, `idp_helpers.go`, `idp_document.go`, `route.go` — warden-as-IdP routing, minting, discovery/JWKS.
- `types.go` — `RequestData`, sentinel errors. `errors.go` — `classifyError` (sentinel → HTTP).
- `validation.go` — body parsing. `audit.go` — audit record. `reqcontext.go` — request ID / client IP.
- `apigateway.go`, `apigatewayv2.go`, `alb.go`, `lambdaurl.go` — adapters; event parse/serialize only.

## Rules

- One `cfg := provider.Get()` per request, passed as `input.Config`; extraction and authorization must see the same generation.
- Claims enter only through `ClaimsExtractorInterface`; adapters never call the validator. Delegated adapters use `ParseRoleOnlyRequestBody`.
- Failures are sentinel errors in `types.go`, mapped only by `classifyError`.
- Log through `logevent` with the request logger and `ctx`; never token material. Claim values go through `subjectAttr` / `cfg.LogClaimValues`.
- Adapters derive request identity through `reqcontext.go` only.
- Under `AuditEnforced()`, the audit write precedes returning credentials.
- `AssumeRole` is never sent more than 1h; longer goes through the IdP (`selectIdP`). `idp.only` has no `AssumeRole` fallback.
- Lambda mains use `lambda.StartWithOptions(..., lambda.WithEnableSIGTERM(bootstrap.Cleanup))`; a deferred cleanup never runs.
- Test the processor with extractor mocks, not `TokenValidatorInterface`.
