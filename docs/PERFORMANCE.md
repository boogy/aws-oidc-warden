# Performance at Scale

How the service behaves with a configuration holding thousands of repositories, and which costs grow with config size.

## How to read these numbers

Every figure below was measured on this hardware:

```
goos: darwin  goarch: arm64  cpu: Apple M4 Max  go: 1.27.0
go test ./internal/config/ -run '^$' -bench 'BenchmarkDecide|BenchmarkValidateLarge' -benchmem -count=10
```

summarized with [benchstat](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat); variation across the 10 runs was within ±3% for every row.

**An M4 Max core is considerably faster than a Lambda ARM64 (Graviton) vCPU, so treat the absolute nanoseconds as a floor, not as a Lambda SLA.** What carries across hardware is the _shape_ of each cost — whether it is flat or linear in config size, and how many allocations it makes. Those are properties of the algorithm, and they are the reason this page exists. Where a conclusion depends on absolute time, it is stated as a bound that still holds if the target core is several times slower.

The benchmarks measure this service's own work only. They exclude every network round trip (JWKS fetch, STS `AssumeRole`, S3 policy read), which in production dominate everything on this page — see [Perspective](#perspective).

**Two config shapes are measured, and the difference is large.** Both use single-organization subjects (`acme/repo0…repoN`) with a session policy and five condition predicates per mapping including a nested `any_of`. They differ in whether those predicates are _shared_:

- **Shared conditions** — every mapping gates on the same patterns (`ref: refs/heads/main`). The common shape, and what `role_groups` produces.
- **Distinct conditions** — every mapping gates on its own patterns (`ref: refs/heads/main<N>`). The worst case for load cost and memory.

Per-request cost is identical either way; load time and memory are not. Where only one number is given, the shape does not affect it. Source: [`internal/config/scale_bench_test.go`](../internal/config/scale_bench_test.go).

## Per-request authorization

The full per-request decision — subject match, condition evaluation, role union, session-policy and session-name resolution — against configs of increasing size:

| Repositories | Time   | Memory | Allocations |
| -----------: | ------ | ------ | ----------- |
|          100 | 475 ns | 136 B  | 7           |
|        1,000 | 490 ns | 136 B  | 7           |
|        5,000 | 499 ns | 136 B  | 7           |
|       10,000 | 500 ns | 136 B  | 7           |

**Flat.** A 100× larger configuration costs 5% more per request, and the allocation profile does not move at all. Literal `owner/repo` subjects are bucketed into an exact-match map at load time ([`internal/config/index.go`](../internal/config/index.go)), so a decision hashes straight to its candidates instead of scanning the config. Only the mappings that actually match have their conditions evaluated, which is why the shared/distinct distinction does not reach this path.

Adding repositories does not make authorization slower.

## Wildcard subjects

Wildcard patterns cannot be hashed, so every wildcard sharing the requested owner is scanned and re-matched. Against a fixed 2,000 literal mappings:

| Wildcard mappings under the same owner | Time    | Memory  |
| -------------------------------------: | ------- | ------- |
|                                     10 | 701 ns  | 224 B   |
|                                    100 | 2.34 µs | 1.0 KiB |
|                                    500 | 10.8 µs | 4.1 KiB |

**Linear in the wildcard count, not in the config size.** This is the one request-path shape that scales with growth, so prefer literal `owner/repo` subjects and reserve wildcards for genuine patterns. Even the worst row is ~11 µs and stays negligible against a single AWS API call; the reason to keep wildcards few is specificity and reviewability first, speed second.

## Configuration load and hot reload

Parsing and validating a config — compiling every anchored regex, resolving role sets and groups, and building the authorization index:

| Repositories | Shared conditions | Distinct conditions |
| -----------: | ----------------- | ------------------- |
|        1,000 | 4.15 ms           | —                   |
|        5,000 | 20.2 ms           | 45.9 ms             |
|       10,000 | 41.4 ms           | —                   |

Linear in both shapes, at roughly 4 ms per 1,000 mappings when conditions are shared and roughly 9 ms per 1,000 when every mapping carries its own patterns. Each distinct subject and condition pattern is compiled once per load and then shared, so repetition is close to free while variety is not: at 5,000 mappings the distinct shape costs **2.3× the time and 2.8× the allocation** (104 MB vs 37 MB churn) of the shared one.

This cost is paid at cold start and again on each remote-config refresh — never on a request that does not trigger a reload. A 10,000-repository config adds ~41 ms to a Lambda cold start on this hardware in the shared shape, and proportionally more on a slower core.

If load time matters at your scale, express repeated gates through `role_groups` rather than repeating them per mapping.

## Memory footprint

Resident heap after loading and validating, measured with `runtime.MemStats` around a forced GC:

| Repositories | Shared conditions | Distinct conditions |
| -----------: | ----------------- | ------------------- |
|        5,000 | 28.2 MB           | 59.3 MB             |
|       10,000 | 56.3 MB           | 118.7 MB            |

About **5.6 KB per mapping** with shared conditions and **11.9 KB per mapping** with distinct ones — the compiled patterns are the difference, and both scale cleanly linearly.

**Sizing guidance** (arithmetic on the figures above, not separately measured): budget the resident figure, plus the Go runtime and AWS SDK, and _double the config_ for hot reload — a refresh briefly holds the old and new config at once.

| Config                    | Resident | Reload peak | Suggested Lambda memory |
| ------------------------- | -------- | ----------- | ----------------------- |
| 5,000 mappings, shared    | 28 MB    | ~56 MB      | 128 MB                  |
| 10,000 mappings, shared   | 56 MB    | ~113 MB     | 256 MB                  |
| 10,000 mappings, distinct | 119 MB   | ~237 MB     | 512 MB                  |

The last row is the one to watch: a 10,000-mapping config with per-mapping conditions does not fit a 128 MB Lambda at all, and will not survive a hot reload at 256 MB. Lambda also scales CPU with memory, so a larger setting shortens the cold-start validation above as a side effect.

## Concurrency

The read path takes no locks — a request evaluates against an immutable config snapshot, and hot reload swaps a new one in atomically. On the same 2,000-literal / 100-wildcard config:

| Mode            | Time per decision |
| --------------- | ----------------- |
| Serial          | 2.34 µs           |
| 16-way parallel | 379 ns            |

About 6× throughput across 16 hardware threads. This matters for the local server mode; a Lambda invocation handles one request per environment, so it reads the serial column.

## Perspective

A decision against a 10,000-repository config costs **~500 ns**. Even assuming a target vCPU five times slower than this one, that is ~2.5 µs.

The work surrounding it is network-bound and milliseconds-scale: the STS `AssumeRole` call, the JWKS fetch on a cache miss, and the S3 read for a policy file or the audit record. None of these are measured here, and all are three or more orders of magnitude larger than the authorization step.

The practical conclusion is that **configuration size is not a request-latency concern for this service.** The costs worth managing at scale are cold-start validation time and heap footprint — both linear, both sensitive to whether conditions are shared, and both documented above.

## Reproducing

```sh
# Per-request and validation benchmarks
go test ./internal/config/ -run '^$' -bench 'BenchmarkDecide|BenchmarkValidateLarge' -benchmem -count=10

# Compare a change against a baseline
go test ./internal/config/ -run '^$' -bench . -benchmem -count=10 > new.txt
benchstat old.txt new.txt
```

Report benchmark results with the `goos`/`goarch`/`cpu` header the Go tool prints. A number without its hardware is not a measurement.
