# OpenTofu Deployment

Provisions AWS OIDC Warden as an API Gateway (HTTP v2 or REST v1) fronting a
Lambda, with the config, cache, and log buckets/tables it needs. See the
[root README](../../README.md) and [docs/ARCHITECTURE.md](../../docs/ARCHITECTURE.md)
for what the service does; this file covers deploying it with this stack.

## Usage

```bash
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars: region, issuer(s), role_mappings, assumable_role_arns

./build.sh                 # self mode (default) — see jwt_validation_mode below
tofu init
tofu plan  -var-file=terraform.tfvars
tofu apply -var-file=terraform.tfvars
```

`terraform.tfvars.example` is the annotated reference for every variable this
stack exposes; `variables.tf` has the authoritative descriptions and
validation rules.

## Key decisions

- **`issuer`/`audiences` vs. `issuers`** — the singular pair renders one
  GitHub Actions issuer entry (today's default). Set `issuers` instead for
  multiple issuers or non-GitHub providers; the two are mutually exclusive.
  `config.yaml` is rendered by the module either way — no hand-managed config
  file needed.
- **`jwt_validation_mode`** — `"self"` (default) validates the JWT signature
  inside the Lambda; `"apigw"` provisions one API Gateway JWT Authorizer +
  route per issuer, so invalid tokens are rejected at the gateway before the
  Lambda is invoked (`api_gateway_type` must be `"http"`; at most 10
  authorizers per HTTP API). `"alb"` mode is not provisioned by this stack —
  it needs the `alb` Lambda binary behind an Application Load Balancer.
- **`api_gateway_type`** — `"http"` (default, v2) supports the JWT
  Authorizer; `"rest"` (v1) supports attaching AWS WAF (`enable_waf`) for
  rate limiting instead of per-route token validation.

## Outputs

| Output                 | Notes                                                                 |
| ----------------------- | ---------------------------------------------------------------------- |
| `api_endpoint`          | Invoke URL for self mode and the `rest` type. **`null` in `apigw` mode** — use `route_endpoints` instead. |
| `route_endpoints`       | Per-issuer invoke URLs, keyed by issuer name, in `apigw` mode; empty otherwise. |
| `waf_web_acl_arn`       | `null` unless `api_gateway_type = "rest"` and `enable_waf = true`. |
| `lambda_function_name`  | |
| `execution_role_arn`    | |
| `config_bucket`         | |
| `cache_table_name`      | `null` unless `enable_dynamodb_cache = true`. |

## Upgrading

### Self mode

No action needed. The `moved` block in `modules/apigateway/main.tf` migrates
`aws_apigatewayv2_route.this` to `aws_apigatewayv2_route.open[0]`
automatically on the next `tofu apply`.

### apigw mode

Existing `apigw`-mode deploys carried a single issuer's authorizer and route
at fixed addresses (`aws_apigatewayv2_authorizer.jwt[0]` /
`aws_apigatewayv2_route.this`). This version keys both by issuer name in
`var.issuers`/`var.jwt_authorizers`, and a `moved` block cannot target an
arbitrary map key — so before running `tofu apply` against this version, move
each resource by hand, or the plan destroys and recreates the authorizer and
route (a brief window where the endpoint 404s):

```bash
tofu state mv 'module.apigateway[0].aws_apigatewayv2_authorizer.jwt[0]' 'module.apigateway[0].aws_apigatewayv2_authorizer.jwt["github"]'
tofu state mv 'module.apigateway[0].aws_apigatewayv2_route.this' 'module.apigateway[0].aws_apigatewayv2_route.jwt["github"]'
```

Replace `"github"` with whichever key you choose for that issuer in
`var.issuers` (or the shorthand's implicit key, also `"github"`, if you keep
using `issuer`/`audiences`). The leading `[0]` is the root module's `count` on
the `apigateway` module call, not part of the migration — leave it as-is.

If this README and the comment above the `moved` block in
`modules/apigateway/main.tf` ever disagree, the comment in the code is
authoritative.

After migrating, `api_endpoint` reads as `null`; read the new
`route_endpoints` output for the per-issuer invoke URLs.
