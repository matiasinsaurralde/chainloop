# Chainloop OSS — Security Audit (New Findings)

**Date:** 2026-09-09
**Target:** `chainloop-dev/chainloop` working tree (branch base `main`, incl. commits through `bc95e6c`, Sept 8 2026)
**Scope of interest:** remotely-triggerable (gRPC / HTTP) attacks — authenticated or unauthenticated — leading to exfiltration, process crash, injection (RCE etc.), account/organization takeover.
**Baseline:** every item below was cross-referenced against the 30 previously-reported open findings (F1–F30, "Remaining Open Findings — Chainloop OSS, Sept 4th 2026") and the items verified-fixed there. Nothing here re-reports F1–F30; where a new finding shares a *root-cause class* with a reported one, that relationship is stated explicitly.

Method: source review of the control plane, artifact-CAS, and shared `pkg/` trees, concentrated on code changed since the Sept-4 baseline, plus targeted end-to-end validation (compiled Go PoCs and data-flow tracing from the remote entrypoint to the sink). Findings are ranked by exploitability/impact, most serious first. Items that are plausible but were **not** reproduced end-to-end are in §"Unconfirmed / needs-triage" at the bottom, per the brief.

---

## Summary table

| ID | Severity | Title | Component | Auth | Validated |
|----|----------|-------|-----------|------|-----------|
| **N1** | **High** | Poisoned attestation permanently DoSes `WorkflowRun.View` (null policy-violation, survives store → panics on every read) | Control plane | Low-priv (attestation push) | **Yes — PoC** |
| **N2** | **Medium-High** | Cross-project policy-evaluation **exfiltration** via attacker-controlled `policyEvaluationsRef` digest (View resolves it with no project RBAC scope) | Control plane | Low-priv (member of 1 project) | **Yes — code** |
| **N3** | Medium | CAS `ResourceService/Describe` has **no role check** → uploader-only token reads any digest's metadata/existence | Artifact CAS | Any CAS token | **Yes — code** (refines F8) |
| **N4** | Low-Medium | Prometheus metrics endpoint auth bypasses **token revocation** and token **scope** | Control plane | Any signed token for the org | **Yes — code** |
| **N5** | Low | Cross-tenant **attestation-digest existence oracle** (`FindByAttestationDigest`, no org predicate) | Control plane | Low-priv (attestation push) | **Yes — code** (F26-class) |
| **N6** | Medium (client-side) | SSRF + local file read via workflow-contract **policy loaders** (`http(s)://`, `file://`) during crafting | CLI/crafter | Contract author | **Yes — code** |

Plus store-time panics (§N1 note), and several unconfirmed items in the last section.

---

## N1 — Poisoned attestation permanently DoSes the WorkflowRun View API (stored, cross-user) — **High**

**Class:** process crash / persistent denial of service. Distinct from the reported F16 (which is a *transient* per-request panic in `referrer.go` annotation type-assertions) and F20 (byte-size amplification): here the malicious attestation is **accepted and persisted**, and it is the **read** path that crashes, for every viewer, indefinitely.

**Affected components / code**
- Sink: `app/controlplane/internal/service/attestation.go:607-612` — `extractPolicyEvaluations()`:
  ```go
  for _, vi := range ev.Violations {          // ev.Violations = []*PolicyViolation
      out := &cpAPI.PolicyViolation{
          Subject:  vi.Subject,               // <-- nil-pointer deref if vi == nil
          Message:  vi.Message,
          ...
  ```
- Read entrypoint: `WorkflowRunService/View` → `app/controlplane/internal/service/workflowrun.go:443` `bizAttestationToPb()` → `attestation.go:585` `extractPolicyEvaluations(predicate.GetPolicyEvaluations())`.
- Store entrypoint: `AttestationService/Store` → `biz/workflowrun.go` `SaveAttestation`.

**Prerequisites / vector.** Any principal able to push an attestation to a workflow (a normal CI **robot account**, an **API token**, or a user token with attestation capability). The attacker fully controls the in-toto predicate JSON — it is the base64 payload inside the DSSE envelope of the bundle they upload and self-sign, so signature verification passes on their own bundle.

**Why it survives store but crashes read.** A JSON `null` array element decodes to a **nil pointer**. At store time the predicate is only inspected through length/counter accessors:
- `ExtractPredicate` (the enclosing `ev` is non-nil, so no panic),
- `GetMaterials()` (`v02.go:518`),
- `GetPolicyEvaluationStatus()` → `summarizeInlineEvaluations()` (`v02.go:581`) which touches only `ev.Gate` and `len(ev.Violations)`.

The nil `*PolicyViolation` is **counted but never dereferenced**, so the run is verified (self-signed), persisted, and `MarkAsFinished(...Success)`. A grep confirms the **only** place in the whole control plane that dereferences an individual violation element is the read-path sink at `attestation.go:610`.

Then every `WorkflowRunService/View` of that run calls `extractPolicyEvaluations` → nil deref → the gRPC recovery middleware (`server/grpc.go:186`) converts it to a 500. The poison lives in the stored bundle, so **the run is permanently un-viewable for every user** who can read that project (auditors, org admins, the web dashboard, `chainloop wf run describe`).

**PoC (validated — runs green against the real package):**
```go
// pkg/attestation/renderer/chainloop package test
statement := `{"_type":"https://in-toto.io/Statement/v1",
 "predicateType":"chainloop.dev/attestation/v0.2",
 "subject":[{"name":"x","digest":{"sha256":"abc"}}],
 "predicate":{"policyEvaluations":{"k":[{"name":"p","violations":[null]}]}}}`
env := &dsse.Envelope{PayloadType:"application/vnd.in-toto+json",
    Payload: base64.StdEncoding.EncodeToString([]byte(statement)),
    Signatures: []dsse.Signature{{Sig:"AA=="}}}

pred,_ := ExtractPredicate(env)
_ = pred.GetMaterials()              // store-time: does NOT panic
_ = pred.GetPolicyEvaluationStatus() // store-time: does NOT panic  -> bundle persists
for _,evs := range pred.GetPolicyEvaluations() {
    for _,ev := range evs {
        for _,vi := range ev.Violations { _ = vi.Subject } // read-time: PANIC (nil deref)
    }
}
```
Result: store-time survives, read-time panics — exactly mirroring `attestation.go:610`.

**Fix.** Skip/reject nil elements in `extractPolicyEvaluations` (`if vi == nil { continue }`), and reject `null` array elements at store-time predicate validation so poisoned evidence is never persisted.

> **Related secondary (transient, per-request 500 — lower severity, borders F16):** a `null` **material** (`{"materials":[null]}`) panics at *store* time in `normalizeMaterial(nil)` (`v02.go:605`), and a `null` **policyEvaluation** (`{"policyEvaluations":{"k":[null]}}`) panics at *store* time in `ExtractPredicate`. Both are caught by the recovery middleware (500) and are *not* persisted, but can leave a run stuck mid-store. Same nil-element root cause; worth fixing in the same pass with comma-ok / nil guards.

---

## N2 — Cross-project policy-evaluation exfiltration via attacker-controlled `policyEvaluationsRef` digest — **Medium-High**

**Class:** IDOR / cross-tenant (cross-project) data exfiltration. Same *class* as the reported F5 (dispatcher downloads by attacker-declared digest) and the fixed CF-M7 (casredirect), but a **distinct, unfixed location**: the `WorkflowRun.View` inline policy-evaluation resolver added/refactored by #3408 (`0a3859a`).

**Affected components / code**
- `app/controlplane/internal/service/workflowrun.go:410` — View authorizes only the **run's own** project:
  `authorizeResource(ctx, PolicyWorkflowRunRead, ResourceTypeProject, run.Workflow.ProjectID)`.
- `app/controlplane/internal/service/workflowrun.go:432` — then resolves an **attacker-controlled** digest:
  `s.resolvePolicyEvaluations(ctx, predicate.GetPolicyEvaluationsRef(), run.Workflow.OrgID)`.
- `app/controlplane/internal/service/workflowrun.go:158` — the resolver passes **`nil`** RBAC scopes:
  `s.casMappingUC.FindCASMappingForDownloadByOrg(ctx, digest, []uuid.UUID{orgID}, nil)`.
- `app/controlplane/pkg/data/casmapping.go:131-134` — `scope, rbacEnabled := scopes[o]`; with `nil` scopes `rbacEnabled=false`, so the predicate is just `casmapping.OrganizationID(o)` — **whole org, no project/product filter**.

Contrast: the download path `casredirect.go:91` was fixed (PFM-6716 / `e2dde78`) to pass `s.rbacScopesForOrg(ctx, orgID)`; this View resolver still passes `nil`.

**Prerequisites / vector.** An authenticated org member who (a) can push an attestation to *any one* project in the org and read their own run, and (b) knows the **sha256 digest** of the target project's policy-evaluation bundle. Steps:
1. Craft an attestation whose predicate sets `policyEvaluationsRef.digest.sha256 = <victim project's policy-eval bundle digest>`, push it to the attacker's own run (project the attacker controls).
2. Call `WorkflowRunService/View` on that run. View authorizes the *run's* project (attacker's own → allowed), then `resolvePolicyEvaluations` looks up the ref digest **org-wide with no project filter**, downloads it (bundles ≤10 MiB are inlined, per #3408), and returns the decoded policy evaluations in the response.
3. The attacker receives another project's policy-evaluation data — violation subjects/messages, vulnerability findings, SAST results, license findings, policy bodies.

**Impact.** Cross-project disclosure of policy-evaluation evidence within an org (the exact data project-RBAC is meant to isolate). Constrained by the need to know the target bundle digest, which is why this is Medium-High rather than High.

**Validated?** Yes — data flow traced entrypoint→sink; the `nil`-scope → `rbacEnabled=false` → whole-org predicate behavior is confirmed in `casmapping.go`.

**Fix.** Pass real scopes: `s.rbacScopesForOrg(ctx, orgID)` (as `casredirect.go` does) into `FindCASMappingForDownloadByOrg` in `resolvePolicyEvaluations`. Optionally require the ref digest to be one recorded for *this* run.

---

## N3 — CAS `ResourceService/Describe` has no role check (metadata/existence oracle) — **Medium**

**Class:** missing authorization. This **refines and confirms** the "add a role check to `Describe`" sub-item noted in F8's remediation, with the concrete observation that an **uploader-only** token suffices.

**Affected components / code**
- `app/artifact-cas/internal/service/resource.go:43-69` — `Describe` calls `InfoFromAuth` (JWT only) then `b.Describe(ctx, req.Digest)` and returns `{Digest, FileName, Size}` with **no `CheckRole`**.
- Every sibling handler enforces a role: `bytestream.go:74` (Write→Uploader), `bytestream.go:355` (Read→Downloader), `download.go:76` (HTTP download→Downloader). `Describe` alone does not.

**Prerequisites / vector.** Any valid CAS JWT — including a write-only CI **uploader** token. `grpcurl -H 'authorization: bearer <uploader-jwt>' -d '{"digest":"sha256:<hex>"}' <cas>:9000 cas.v1.ResourceService/Describe` returns filename + exact size + existence for any digest served by the token's backend, a read capability an uploader is never granted. Scope: all projects in the token's org (extends F8's cross-project IDOR to the metadata surface); cross-tenant if an operator shares a non-access-point backend across orgs.

**Validated?** Yes — the role check is simply absent, verified against the three sibling handlers.

**Fix.** Add `if err := info.CheckRole(casJWT.Downloader); err != nil { return nil, err }` to `Describe` (and bind the token to authorized digests to fully close F8).

---

## N4 — Prometheus metrics endpoint bypasses token revocation and token scope — **Low-Medium**

**Class:** authentication weakness (revocation bypass) + minor cross-project info disclosure.

**Affected components / code**
- `app/controlplane/internal/server/http.go:72-80` wires `service.PrometheusMetricsPath` (`/prom/{org_name}/metrics`) through `middlewares_http.AuthFromAuthorizationHeader(...)` — note the comment at `http.go:69`: *"these non-grpc transcoded methods DO NOT RUN the middlewares."*
- `pkg/middlewares/http/jwt.go:69` → `verifyAndMarshalJWT` performs **JWT signature + expiry + signing-method** checks only. No DB lookup.
- The normal API-token path, by contrast, loads the token and rejects it if revoked: `usercontext/apitoken_middleware.go:164` (`token.RevokedAt != nil → "API token revoked"`), and runs the authz/scope middleware.
- `service/prometheus.go:76` only checks `apiTokenClaims.OrgName == org_name` from the path.

**Prerequisites / vector.** Any validly-signed, non-expired API token whose `org_name` claim matches the path (a **project-scoped** token qualifies). Because the endpoint never consults the DB:
- a **revoked** (but not-yet-expired) API token still authenticates and returns metrics;
- a **project-scoped** token reads the whole org's metrics (no scope/authz check).

Gated on the org having a Prometheus integration enabled.

**Validated?** Yes — code paths confirmed (JWT-only helper vs. DB revocation check on the normal path).

**Fix.** Route the Prometheus handler through the same revocation + scope checks as other API-token operations (resolve the token in the DB and honor `RevokedAt` and scope), rather than JWT-signature-only auth.

---

## N5 — Cross-tenant attestation-digest existence oracle — **Low**

**Class:** existence oracle / info disclosure. Same class as the reported F26 (`data/referrer.go Exist` has no org predicate), at a **distinct location**.

**Affected components / code**
- `app/controlplane/pkg/data/workflowrun.go:221` — `FindByAttestationDigest(digest)` queries `workflowrun.AttestationDigest(digest)` with **no org predicate**.
- `app/controlplane/pkg/biz/workflowrun.go:~491-500` — `SaveAttestation` iterates attacker-controlled `predicate.GetMaterials()` and, for each material of `type=ATTESTATION`, calls `FindByAttestationDigest(m.Hash.String())`, returning a distinct `"dependent attestation not found: <digest>"` error when absent — **no org re-check** (unlike `GetByDigestInOrg`, `biz/workflowrun.go:674`, which re-checks `wfrun.Workflow.OrgID`).

**Prerequisites / vector.** Any credential that can store an attestation in the attacker's own org. Craft a bundle whose predicate embeds a material `{type:"ATTESTATION", hash:"<target digest in another org>"}`; a distinct error vs. success reveals whether that exact attestation digest exists anywhere on the platform.

**Validated?** Yes — unscoped sink reached from `Store`→`SaveAttestation`. Low impact (boolean existence only, no data returned).

**Fix.** Thread org scope into the dependent-attestation existence probe (use an `InOrg` variant).

---

## N6 — SSRF + local file read via workflow-contract policy loaders (client-side) — **Medium (CI-runner trust boundary)**

**Class:** SSRF / local file disclosure. Distinct mechanism from the reported F19 (`http.send` in Rego): this is the policy **loader** that fetches a referenced policy before evaluation. **Trust boundary is the CI runner** (evaluation is client-side — see "Key negative results"), i.e. contract-author → CI-runner network + filesystem.

**Affected components / code**
- `pkg/policies/loader.go:141` — `HTTPSLoader`: `resp, err := http.Get(ref)` (`// #nosec G107`), `ref = attachment.GetRef()`; no allowlist, no `#3407` dial guard, no timeout.
- `pkg/policies/loader.go:115` — `FileLoader`: `os.ReadFile(filepath.Clean(filePath))` from the ref.
- Dispatch: `pkg/policies/policies.go` `getLoader()` selects the loader by ref scheme during `chainloop attestation add/push`.

**Prerequisites / vector.** Ability to author/edit a workflow contract (or control any policy a contract references). A `ref` of `http://169.254.169.254/...` reaches cloud metadata / internal hosts from the CI runner; `file:///etc/...` reads runner-local files whose contents can surface via policy behavior. The `#3407` SSRF-hardened client was applied to integration fan-out plugins, **not** to these policy loaders.

**Validated?** Yes (code-level). Reachable only through the CLI/crafter, not a control-plane RPC — hence listed after the server-side findings.

**Fix.** Route loader HTTP through the `#3407` public-targets-only client (with a timeout), and gate/allowlist `file://` refs.

---

## Key negative results (validated — narrow the attack surface)

These materially bound the threat model and were confirmed during the audit:

- **Policy evaluation (Rego/WASM) is client-side only.** Neither the control plane nor artifact-cas imports or runs an OPA/WASM engine (`grep` for `open-policy-agent/opa`, `wazero`, `engine.Verify` across both server trees: zero non-test hits). `NewPolicyVerifier` is constructed only in the crafter/CLI. → **No server-side Rego RCE/SSRF** (the F19 `http.send` risk is correctly a CI-runner concern).
- **Material contents are parsed client-side only.** The control plane never calls `ValidateSecurityContext` / `ValidateAICodingSession` / material `.Craft()`. The new material parsers (CHAINLOOP_AI_SECURITY_CONTEXT #3376/#3411, AI coding session #3368, trace #3388/#3415) are therefore **client** self-DoS surfaces, not remote server crashes. Server-side annotation handling is the already-reported F16 path.
- **Token/auth machinery is hardened.** User/API/robot HMAC tokens share one secret but are separated by an **audience** claim checked at every verification point; `runProviderValidator` rejects signing-method mismatch (closes `none`/alg-confusion); CAS tokens are a separate ES512 asymmetric domain; the authz middleware is **default-deny** (empty subject → Forbidden; unknown op → denied), so a robot/attestation token cannot be confused into control-plane access. OIDC state is cookie-bound and `callbackAllowed` blocks the open-redirect variants (CF-H3/CL-H5 fixed). Instance-admin (cross-org) API tokens cannot be minted via the public `Create` (org is always the caller's).
- **The #3407 SSRF dial guard is correctly built** (dial-time re-resolution + dialing the validated IP → no TOCTOU; every redirect hop re-checked; thorough IPv4/IPv6 classification incl. IPv4-mapped/NAT64/CGNAT/link-local; proxy disabled under public-targets-only). No parser/allowlist bypass found in `plugins/sdk/v1/httpclient.go`. (`block_private_targets` defaulting off is the deliberate, already-reported F4 posture.)
- **Other fixes verified complete:** jsonfilter SQLi fix (CL-H2) — anchored allowlist + parameterized values, no bypass; `casredirect` download RBAC (CF-M7); #3408 bounded-buffer inline cap; archive extraction (`archiveio`) enforces entry/size limits and rejects path traversal.

---

## Unconfirmed / needs-triage (plausible, not reproduced end-to-end)

Per the brief, items that are likely but not validated end-to-end:

1. **CAS gRPC *streaming* handlers lack panic recovery.** `app/artifact-cas/internal/server/grpc.go` installs `recovery.Recovery()` for unary handlers; the streaming interceptor chain (bytestream Write/Read) does not. A panic in a streaming handler would crash the whole CAS process. No reliable attacker-controlled trigger was found (the gob decode on the Write path returns errors rather than panicking), so this is a latent defense-in-depth gap rather than a proven crash. *Fix: add stream recovery.*
2. **azureblob digest → URL query/fragment injection.** The gRPC Read/Describe paths do not strictly validate that `req.Digest` is a `sha256:<hex>` before it is used to build the blob URL (the HTTP `/download/{digest}` path *does*, via `cr_v1.NewHash`). Whether `?`/`#` in a digest can redirect the azureblob request is SDK-behavior-dependent and was not confirmed against a live backend. *Fix: validate digest format at the gRPC boundary too.*
3. **CAS download token exposed in URL/logs.** The HTTP download uses `?t=<jwt>` and the kratos `logging.Server` records `r.RequestURI`; the CAS downloader token may land in access logs (an F9-class exposure for the data-plane token). Not traced to a concrete log sink in this pass.
4. **Federated-delegation middleware unchecked type assertion.** `(*claims)["orgId"].(string)` in the federated provider middleware is an unchecked assertion; it panics only if a *trusted* federated IdP emits a non-string `orgId`, so it is low-risk (trusted-provider data) but should be comma-ok.
5. **Verifier "TSA trust-config fault" acceptance (#3396).** `SaveAttestation` now *accepts and stores* an attestation whose timestamp fails verification when classified `TrustConfigFault` (`ErrNoTSARootsConfigured` / `ErrTSASignerNotTrusted`), logging a warning. The DSSE signature is still verified independently, so this is a deliberate, documented weakening of the *timestamp* guarantee (secondary control) rather than a signature bypass — flagged for review, not a confirmed exploit.

---

*Prepared as a source-level audit. Findings N1–N6 were validated end-to-end (PoC or entrypoint→sink data-flow trace); §"Unconfirmed" lists plausible items not reproduced. No changes were made to product code.*
