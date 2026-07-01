# Group C — Crypto / time hardening + JWKS fetch

Prereqs: B. Files: `internal/validator/validator.go` (`GenKeyFunc`, `fetchJWKS`, `requireSecureURL`), `internal/cache` (memo).
**Read `SHARED.md` first** — invariants 5, 6, 7.

## Tasks

- **C1 (5a)** In `GenKeyFunc`: after `kid` match require `key.Use == "sig" || ""`, `key.Algorithm == token.Header["alg"]` (when key alg present), **and** key-type↔alg-family (RSA⇒RS*, EC⇒ES*). Duplicate-`kid` different-type JWKS must not select the wrong key.
- **C2 (5b)** Parser `WithLeeway(leeway)`; require `sub` non-empty; `iat` required (for max-age); `nbf` enforced when present.
- **C3 (5d)** Reject `exp-iat > maxTokenLifetime` or `now-iat > maxTokenAge` (when configured).
- **C4 (5c)** Forced-JWKS-refetch limiter — **per-(issuer,kid)** so a genuinely new kid refetches once (rotation works), while a flood of distinct bogus kids is bounded by a per-issuer global rate. Default cooldown 60s. Guard the limiter map with `sync.RWMutex`/`sync.Map`. **Do not** use a long blanket cooldown (V9: it breaks rotation).
- **C5** `requireSecureURL` honors `allow_insecure_issuers` (HTTP/loopback rejected unless set; dev-only).
- **C6 (S7 — SSRF, high)** Harden the JWKS HTTP client: block private/loopback/link-local/metadata IPs (e.g. `169.254.169.254`) at dial time, including on redirects (cap redirects, re-validate scheme+host on each hop); `TLSClientConfig{MinVersion: tls.VersionTLS12}`; `http.NewRequestWithContext`. **Build the client once at init** and reuse (keep-alive) — never per call (current code allocates per call ~validator.go:218).
- **C7 (S8)** Validate the discovery doc's `issuer` == configured issuer (RFC 8414); reject otherwise. Support the per-issuer `jwks_uri` override (skip discovery, still SSRF/HTTPS-checked). Reject + never cache an empty (zero-key) JWKS.
- **C8 (perf)** `singleflight.Group` per-issuer fetch (P1). **In-process** pre-parsed-key memo keyed `(issuer,kid)` (the shared `Cache` still stores JWKS JSON — it can't hold `crypto.PublicKey`); re-validate RSA≥2048 / EC on-curve when populating the memo (S4). Cache the discovered `jwks_uri` to skip re-discovery on refetch (re-discover only on JWKS 404).

## Security review C (ADVERSARIAL)

alg/key/HMAC/`none` confusion; duplicate-kid JWKS; JWKS poisoning (weak key) blocked on memo load; **SSRF / metadata-exfil** incl. redirect bypass; refetch DoS bounded but rotation still works; transport/TLS min version; time-bound bypass (leeway boundary, future-iat, missing iat/exp, lifetime/age).

## Verification slice

- alg confusion: RS256 token with EC key → reject; `alg=none`/`HS256` → reject; `use!=sig` key → reject.
- SSRF: discovery/`jwks_uri` → `127.0.0.1`/`169.254.169.254`/private → reject (and on redirect hop); discovery `issuer` mismatch → reject; zero-key JWKS → reject, not cached.
- rotation: a new kid is accepted within one refetch; flood of distinct bogus kids is rate-bounded.
- singleflight: concurrent cold fetches → 1 upstream call (counting mock issuer); pre-parsed memo bench.
- `make check` + `go test -race ./internal/validator/...` green.

## Commit

`feat(validator): crypto/time hardening, SSRF-safe JWKS fetch, key memo` → update `PROGRESS.md`.
