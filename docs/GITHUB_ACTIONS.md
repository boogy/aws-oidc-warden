# Calling the service from CI

Every example here does the same three things: request an OIDC token, POST it to the warden, export the credentials it returns. What changes between them is who verifies the token, how failures are handled, and where the code lives.

The job always needs `id-token: write`:

```yaml
permissions:
  id-token: write # required to request the OIDC token
  contents: read
```

| Section                                                         | What's inside                                                                      |
| --------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| [Request & response contract](#request--response-contract)      | The wire format for every mode — **read this before writing your own client**      |
| [Basic example](#basic-example-github-script)                   | `github-script`, `self` mode — the shortest thing that works                       |
| [`apigw` mode variant](#apigw-mode-variant)                     | The token moves to the `Authorization` header                                      |
| [Without `github-script`](#without-github-script)               | Plain `curl`, and when to prefer it                                                |
| [Multi-region failover](#multi-region-failover)                 | Two regions, primary first — in both `github-script` and `curl`                    |
| [Ship it as a composite action](#ship-it-as-a-composite-action) | **The recommended rollout** — one component your teams consume, and you can change |
| [Non-GitHub callers](#non-github-callers)                       | GitLab and any other OIDC provider                                                 |

---

## Request & response contract

Which mode the service runs in decides **who verifies the token**, and that changes where the token goes. The role ARN is always in the JSON body.

| Mode             | `Authorization` header                | Request body                      | Token verified by          |
| ---------------- | ------------------------------------- | --------------------------------- | -------------------------- |
| `self` (default) | none                                  | `{"token": "...", "role": "..."}` | This service               |
| `apigw`          | `Bearer <token>`                      | `{"role": "..."}`                 | API Gateway JWT Authorizer |
| `alb`            | none — ALB injects `x-amzn-oidc-data` | `{"role": "..."}`                 | ALB OIDC                   |

**The token is never sent twice.** In `apigw` mode it lives _only_ in the header — a `token` field in the body is ignored, and a missing header makes API Gateway reject the call before this service runs. Even in delegated modes, this service still re-validates every claim. See [TOKEN_VALIDATION.md §2.1](TOKEN_VALIDATION.md#21-request-contract-per-mode).

A success carries live credentials:

```json
{
  "success": true,
  "statusCode": 200,
  "requestId": "12258876-a981-452b-a7ae-415f8fa737b6",
  "data": {
    "AccessKeyId": "ASIA...",
    "SecretAccessKey": "...",
    "SessionToken": "...",
    "Expiration": "2026-09-07T12:34:56Z"
  }
}
```

A failure carries only a classified code — internal detail never reaches the client, so correlate with `requestId` in the logs:

```json
{
  "success": false,
  "statusCode": 403,
  "requestId": "12258876-a981-452b-a7ae-415f8fa737b6",
  "processingMs": 383,
  "message": "Permission denied for the requested operation",
  "errorCode": "permission_denied"
}
```

The status code tells your client whether retrying is worth anything:

| Status                   | Meaning                                                           | Retry or fail over?    |
| ------------------------ | ----------------------------------------------------------------- | ---------------------- |
| `400 invalid_request`    | Malformed body, or a missing `role`                               | **No** — deterministic |
| `401 token_invalid`      | Signature, issuer, audience or time bounds failed                 | **No** — deterministic |
| `403 permission_denied`  | _This service_ refused: no mapping matched, or a condition failed | **No** — deterministic |
| `403 assume_role_denied` | _AWS STS_ refused a role this service authorized (trust policy)   | **No** — deterministic |
| `500 assume_role_failed` | Throttling, expired broker credentials, malformed session policy  | **Yes** — transient    |
| `502` / `503` / timeout  | The endpoint is unhealthy or unreachable                          | **Yes**                |

<!-- prettier-ignore -->
> [!IMPORTANT]
> **The two 403s mean different things, and a client must treat both as final.** `permission_denied` is this service refusing; `assume_role_denied` is STS refusing. Before these were split, a client retrying on "5xx" would fail over on a trust-policy denial and fail twice — writing two audit records for one deterministic error. Full table: [TOKEN_VALIDATION.md](TOKEN_VALIDATION.md#10-failure-modes--http-status).

---

## Basic example (`github-script`)

```yaml
name: AWS Deployment

on: [push]

jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write # required to request the OIDC token
      contents: read

    steps:
      - uses: actions/checkout@v4

      - name: Get AWS credentials via OIDC warden
        uses: actions/github-script@v7
        with:
          script: |
            const core = require('@actions/core');

            // The audience must match the issuer's `audiences` in the warden config.
            const token = await core.getIDToken('sts.amazonaws.com');

            const response = await fetch('https://your-api-id.execute-api.eu-west-1.amazonaws.com/prod/verify', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                token: token,
                role: 'arn:aws:iam::123456789012:role/github-actions-role'
              })
            });

            if (!response.ok) {
              core.setFailed(`warden request failed: ${response.status} ${await response.text()}`);
              return;
            }

            const { data } = await response.json();
            core.setSecret(data.AccessKeyId);
            core.setSecret(data.SecretAccessKey);
            core.setSecret(data.SessionToken);
            core.exportVariable('AWS_ACCESS_KEY_ID', data.AccessKeyId);
            core.exportVariable('AWS_SECRET_ACCESS_KEY', data.SecretAccessKey);
            core.exportVariable('AWS_SESSION_TOKEN', data.SessionToken);

      - name: Use the credentials
        run: aws sts get-caller-identity
```

**The `setSecret` calls matter.** Without them the credentials can be printed to the job log by any later step. Call `setSecret` _before_ `exportVariable`, so masking is in place before the value can reach the log.

---

## `apigw` mode variant

In `apigw` mode the API Gateway JWT Authorizer verifies the signature, so the token moves to the header and the body carries only the role. Only the `fetch` call changes:

```yaml
- name: Get AWS credentials via OIDC warden (apigw mode)
  uses: actions/github-script@v7
  with:
    script: |
      const core = require('@actions/core');
      const token = await core.getIDToken('sts.amazonaws.com');

      const response = await fetch('https://your-api-id.execute-api.eu-west-1.amazonaws.com/prod/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          role: 'arn:aws:iam::123456789012:role/github-actions-role'
        })
      });

      // ...same handling as above
```

The audience passed to `getIDToken(...)` must match **both** the API Gateway JWT Authorizer's configured audience and the issuer's `audiences` in the warden config. A mismatch is rejected by the gateway before this service ever runs.

---

## Without `github-script`

`curl` against `$ACTIONS_ID_TOKEN_REQUEST_URL` works too, but you have to append the audience yourself and mask the credentials by hand:

```yaml
- name: Get AWS credentials via OIDC warden
  run: |
    TOKEN=$(curl -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
      "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" | jq -r '.value')

    CREDS=$(curl -sSf -X POST https://your-endpoint/verify \
      -H 'Content-Type: application/json' \
      -d "{\"token\":\"$TOKEN\",\"role\":\"arn:aws:iam::123456789012:role/github-actions-role\"}")

    for k in AccessKeyId SecretAccessKey SessionToken; do
      echo "::add-mask::$(echo "$CREDS" | jq -r ".data.$k")"
    done
    echo "AWS_ACCESS_KEY_ID=$(echo "$CREDS" | jq -r '.data.AccessKeyId')" >> "$GITHUB_ENV"
    echo "AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | jq -r '.data.SecretAccessKey')" >> "$GITHUB_ENV"
    echo "AWS_SESSION_TOKEN=$(echo "$CREDS" | jq -r '.data.SessionToken')" >> "$GITHUB_ENV"
```

| Prefer                  | When                                                                                                                        |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `github-script`         | Clarity matters most — audience control is explicit, masking is harder to forget, and error handling reads as ordinary code |
| `curl` in a `run:` step | **Speed** matters — a `run:` step starts immediately, whereas a JS action must be downloaded before the job can proceed     |

---

## Multi-region failover

Two regional deployments, primary first, secondary only when the primary is genuinely unavailable. The deployment side — what to share, what never to share, and the trust-policy foot-gun — is in [ARCHITECTURE.md § Scaling](ARCHITECTURE.md#scaling).

Both versions below implement the same policy:

1. **One token, reused for every attempt.** Validation is stateless and both regions list the same audience, so re-requesting the token would be pure latency.
2. **Deterministic refusals are final.** `400`/`401`/`403` skip the remaining endpoints — every region shares the authorization config and returns the same answer.
3. **Only unreachable or transient failures fail over.**
4. **Mask before exporting**, on every path.

### With `github-script`

```yaml
- name: Get AWS credentials via OIDC warden
  uses: actions/github-script@v7
  env:
    WARDEN_ENDPOINTS: >-
      https://warden.eu-west-1.example.com/verify, https://warden.eu-central-1.example.com/verify
    ROLE_ARN: arn:aws:iam::123456789012:role/github-actions-role
  with:
    script: |
      const core = require('@actions/core');

      const endpoints = process.env.WARDEN_ENDPOINTS.split(',').map(s => s.trim()).filter(Boolean);
      const role = process.env.ROLE_ARN;
      const timeoutMs = 8000;

      // One token for every attempt: validation is stateless and both regions
      // list the same audience, so re-requesting would be pure latency.
      const token = await core.getIDToken('sts.amazonaws.com');

      for (const url of endpoints) {
        let response;
        try {
          response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token, role }),
            signal: AbortSignal.timeout(timeoutMs),
          });
        } catch (err) {
          // DNS failure, refused connection, or the timeout above.
          core.warning(`${url} unreachable (${err.name}) — failing over`);
          continue;
        }

        if (response.ok) {
          const { data } = await response.json();
          // Mask before exporting: setSecret must be in place before the
          // value can reach the log by any other route.
          core.setSecret(data.AccessKeyId);
          core.setSecret(data.SecretAccessKey);
          core.setSecret(data.SessionToken);
          core.exportVariable('AWS_ACCESS_KEY_ID', data.AccessKeyId);
          core.exportVariable('AWS_SECRET_ACCESS_KEY', data.SecretAccessKey);
          core.exportVariable('AWS_SESSION_TOKEN', data.SessionToken);
          core.setOutput('endpoint', url);
          core.setOutput('expiration', data.Expiration);
          core.info(`credentials issued by ${url}`);
          return;
        }

        // Deterministic refusal: every region shares this authorization config
        // and returns the same answer. Failing over would only delay the real
        // error and write a second audit record.
        if ([400, 401, 403].includes(response.status)) {
          core.setFailed(`warden refused (${response.status}): ${await response.text()}`);
          return;
        }

        core.warning(`${url} unavailable (${response.status}) — failing over`);
      }

      core.setFailed('no warden endpoint could issue credentials');
```

`github-script` wraps the script in an async function, so top-level `await` and `return` both work as written. `AbortSignal.timeout` needs Node ≥ 17.3; `github-script@v7` runs Node 20.

<!-- prettier-ignore -->
> [!NOTE]
> **`fetch` cannot separate the connect timeout from the response timeout.** `AbortSignal.timeout` bounds the whole request, so a blackholed region consumes the full 8s before failover — where the `curl` version below abandons it in ~2s. That is the one real advantage `curl` has here. If you want both the JS ergonomics and the fast abandon, keep two signals: a short one you replace with the long one once the response headers arrive — or just use the composite action, which is `curl` underneath.

### With `curl`

This runs as a plain `run:` step, so there is no action to fetch before it can start.

```yaml
- name: Get AWS credentials via OIDC warden
  env:
    WARDEN_PRIMARY: "https://warden.eu-west-1.example.com/verify"
    WARDEN_SECONDARY: "https://warden.eu-central-1.example.com/verify"
    ROLE_ARN: "arn:aws:iam::123456789012:role/github-actions-role"
  run: |
    set -euo pipefail

    BODY=$(mktemp)
    trap 'rm -f "$BODY"' EXIT   # the response body holds live credentials

    # One token, reused for both regions: validation is stateless, and both
    # regions list the same audience for this issuer.
    TOKEN=$(curl -sS --connect-timeout 3 --max-time 10 \
      -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
      "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" | jq -r .value)

    for URL in "$WARDEN_PRIMARY" "$WARDEN_SECONDARY"; do
      # --connect-timeout is deliberately far shorter than --max-time: a dead
      # region fails the connect phase in ~2s, while a live-but-cold region
      # still gets the full budget to answer.
      CODE=$(curl -sS -o "$BODY" -w '%{http_code}' \
        --connect-timeout 2 --max-time 8 \
        -X POST "$URL" \
        -H 'Content-Type: application/json' \
        -d "{\"token\":\"$TOKEN\",\"role\":\"$ROLE_ARN\"}" || true)

      case "${CODE:-000}" in
        200)
          read -r AKI SAK TOK < <(jq -r '.data | "\(.AccessKeyId) \(.SecretAccessKey) \(.SessionToken)"' "$BODY")
          echo "::add-mask::$AKI"; echo "::add-mask::$SAK"; echo "::add-mask::$TOK"
          { echo "AWS_ACCESS_KEY_ID=$AKI"
            echo "AWS_SECRET_ACCESS_KEY=$SAK"
            echo "AWS_SESSION_TOKEN=$TOK"; } >> "$GITHUB_ENV"
          echo "credentials issued by $URL"
          exit 0
          ;;
        400 | 401 | 403)
          # Deterministic refusal: the other region shares this authorization
          # config and returns the same answer. Failing over would only delay
          # the real error and write a second audit record.
          echo "::error::warden refused ($CODE): $(cat "$BODY")"
          exit 1
          ;;
        *)
          echo "::warning::$URL unavailable ($CODE) — failing over"
          ;;
      esac
    done

    echo "::error::no warden endpoint could issue credentials"
    exit 1
```

### Why this is fast

| Choice                                    | Effect                                                                                                                                                                                                                                |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A `run:` step, not a JS action            | Nothing to download before the step executes                                                                                                                                                                                          |
| One `getIDToken` call, reused             | The token is replayable across regions; a second request would be pure latency                                                                                                                                                        |
| `--connect-timeout 2` with `--max-time 8` | The two failure shapes get different budgets: a **blackholed** region is abandoned in ~2s, while a live region that is merely cold keeps its full 8s. A single flat timeout has to choose between slow failover and spurious failover |
| One `jq` invocation                       | Three separate parses of the same tiny document buy nothing                                                                                                                                                                           |
| Deterministic refusals are final          | `401`/`403` skip the second region entirely — the answer will not differ                                                                                                                                                              |

On the happy path the cost is one token request plus one POST, so the step is dominated by a single round trip to a warm Lambda. When the primary is unreachable, the added cost is the ~2s connect timeout.

<!-- prettier-ignore -->
> [!NOTE]
> **Tune `--max-time` to your cold starts, not below them.** The failover region is cold by definition, and in `self` mode a cold start may include a JWKS fetch (prefetched during Lambda INIT, bounded at 3s). Too tight a value turns an ordinary cold start into a spurious failover — and, with the `403` rule above, an unnecessary second audit record. Provisioned concurrency is the alternative if you want a tighter bound.

<!-- prettier-ignore -->
> [!TIP]
> **Want failover with no wait at all?** Fire both regions concurrently and take the first success (a hedged request — `Promise.any` in the JS version). It removes the wait entirely, at a real cost: when both succeed you have issued **two sets of live credentials** and written **two audit records**, and only one gets used. For a credential broker that is usually the wrong trade — but it is the right one if your tail latency budget is tighter than a couple of seconds.

---

## Ship it as a composite action

Everything above is what teams would otherwise paste into their workflows — and once it is pasted into fifty repositories, the endpoint list, the failover order, the retry predicate and the request shape are all frozen across a fleet you cannot edit.

**Put it behind one composite action instead.** That action becomes the single component you change; teams consume it and never touch the details.

```yaml
# aws-oidc-warden-action/action.yml
name: AWS credentials via OIDC warden
description: Exchange this workflow's OIDC token for short-lived AWS credentials.

inputs:
  role:
    description: Target IAM role ARN to assume.
    required: true
  audience:
    description: OIDC audience. Must match the issuer's `audiences` in the warden config.
    default: sts.amazonaws.com
  mode:
    description: "`self` (token in body) or `apigw` (token in the Authorization header)."
    default: self
  endpoints:
    description: >-
      Comma-separated warden endpoints, tried in order. Defaulted HERE so that adding, moving or reordering a region needs no change in any caller.
    default: https://warden.eu-west-1.example.com/verify,https://warden.eu-central-1.example.com/verify
  connect-timeout:
    description: Seconds to wait for a connection before treating an endpoint as down.
    default: "2"
  max-time:
    description: Seconds to wait for a full response. Must exceed your cold-start time.
    default: "8"

outputs:
  endpoint:
    description: The endpoint that issued the credentials.
    value: ${{ steps.creds.outputs.endpoint }}
  expiration:
    description: Credential expiry, RFC3339.
    value: ${{ steps.creds.outputs.expiration }}

runs:
  using: composite
  steps:
    - id: creds
      shell: bash
      env:
        WARDEN_ENDPOINTS: ${{ inputs.endpoints }}
        ROLE_ARN: ${{ inputs.role }}
        AUDIENCE: ${{ inputs.audience }}
        MODE: ${{ inputs.mode }}
        CONNECT_TIMEOUT: ${{ inputs.connect-timeout }}
        MAX_TIME: ${{ inputs.max-time }}
      run: |
        set -euo pipefail

        if [ -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ]; then
          echo "::error::No OIDC token available — add 'permissions: id-token: write' to the job."
          exit 1
        fi

        BODY=$(mktemp)
        trap 'rm -f "$BODY"' EXIT   # the response body holds live credentials

        TOKEN=$(curl -sS --connect-timeout 3 --max-time 10 \
          -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
          "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=$AUDIENCE" | jq -r .value)

        # The one place the wire contract is encoded. Switching the fleet from
        # self to apigw mode is this branch, not fifty workflow edits.
        case "$MODE" in
          apigw) ARGS=(-H "Authorization: Bearer $TOKEN" -d "{\"role\":\"$ROLE_ARN\"}") ;;
          self)  ARGS=(-d "{\"token\":\"$TOKEN\",\"role\":\"$ROLE_ARN\"}") ;;
          *)     echo "::error::unknown mode '$MODE' (expected self or apigw)"; exit 1 ;;
        esac

        IFS=',' read -ra ENDPOINTS <<< "$WARDEN_ENDPOINTS"
        for URL in "${ENDPOINTS[@]}"; do
          URL="${URL// /}"
          [ -n "$URL" ] || continue

          CODE=$(curl -sS -o "$BODY" -w '%{http_code}' \
            --connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIME" \
            -X POST "$URL" -H 'Content-Type: application/json' \
            "${ARGS[@]}" || true)

          case "${CODE:-000}" in
            200)
              read -r AKI SAK TOK EXP < <(jq -r \
                '.data | "\(.AccessKeyId) \(.SecretAccessKey) \(.SessionToken) \(.Expiration)"' "$BODY")
              echo "::add-mask::$AKI"; echo "::add-mask::$SAK"; echo "::add-mask::$TOK"
              { echo "AWS_ACCESS_KEY_ID=$AKI"
                echo "AWS_SECRET_ACCESS_KEY=$SAK"
                echo "AWS_SESSION_TOKEN=$TOK"; } >> "$GITHUB_ENV"
              { echo "endpoint=$URL"; echo "expiration=$EXP"; } >> "$GITHUB_OUTPUT"
              echo "credentials issued by $URL"
              exit 0
              ;;
            400 | 401 | 403)
              # Deterministic refusal — every endpoint shares the authorization
              # config and returns the same answer.
              echo "::error::warden refused ($CODE): $(cat "$BODY")"
              exit 1
              ;;
            *)
              echo "::warning::$URL unavailable ($CODE) — failing over"
              ;;
          esac
        done

        echo "::error::no warden endpoint could issue credentials"
        exit 1
```

What a team writes then — the entire surface they depend on:

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: my-org/aws-oidc-warden-action@v1
        with:
          role: arn:aws:iam::123456789012:role/gha-payments

      - run: aws sts get-caller-identity
```

### Why this is the right seam

| Change                                            | With the action            | Pasted inline in every repo             |
| ------------------------------------------------- | -------------------------- | --------------------------------------- |
| Add, move or reorder a region                     | One default value          | Every workflow                          |
| Retune `--connect-timeout` / `--max-time`         | One default value          | Every workflow                          |
| Switch `self` → `apigw` (token moves to a header) | One `case` branch          | Every workflow                          |
| Change which statuses fail over                   | One `case` branch          | Every workflow                          |
| Add masking you forgot                            | Once, and everyone gets it | Every workflow you can still track down |

Teams pin `@v1` and receive all of it on their next run.

<!-- prettier-ignore -->
> [!IMPORTANT]
> **This action sees the OIDC token, so treat its repository as production infrastructure.** Anyone who can push to it can exfiltrate every consumer's token and mint credentials. Require reviews, protect the branch and the tags, and restrict who can move `v1`. If your organisation forbids moving tags, teams must pin a SHA — which restores the fleet-wide bump on every endpoint change, so weigh that against the immutability you gain.

Two practical notes: keep the action to a **single `action.yml` with no bundled dependencies**, so the runner's fetch stays negligible — this is the one cost a composite action has over an inline `run:` step. And `curl` and `jq` are preinstalled on GitHub-hosted Ubuntu runners; on self-hosted runners, make sure both exist.

A dedicated repository owned by whoever runs the warden works better than a subdirectory of a service repo — the action's release cadence then stays independent of the service's.

---

## Non-GitHub callers

Nothing above is GitHub-specific on the wire: any client that can obtain an OIDC token from a configured issuer can call the same endpoint with the same body. Only the token-acquisition step changes.

GitLab CI, for example, receives the token as a job variable instead of requesting it:

```yaml
deploy:
  id_tokens:
    AWS_ID_TOKEN:
      aud: sts.amazonaws.com # must match the issuer's `audiences`
  script:
    - |
      CREDS=$(curl -sSf -X POST https://your-endpoint/verify \
        -H 'Content-Type: application/json' \
        -d "{\"token\":\"$AWS_ID_TOKEN\",\"role\":\"$ROLE_ARN\"}")
    - export AWS_ACCESS_KEY_ID=$(echo "$CREDS" | jq -r .data.AccessKeyId)
    - export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | jq -r .data.SecretAccessKey)
    - export AWS_SESSION_TOKEN=$(echo "$CREDS" | jq -r .data.SessionToken)
```

GitLab publishes different claims than GitHub, so the issuer needs `claim_mappings` to say which claim is the canonical subject — see [MULTI_ISSUER.md](MULTI_ISSUER.md).

<!-- prettier-ignore -->
> [!CAUTION]
> **GitLab has no equivalent of `::add-mask::`.** The `export` lines above put live credentials in the job environment with no masking, so any later command that dumps the environment leaks them. Restrict who can read job logs, and prefer the shortest usable session duration.
