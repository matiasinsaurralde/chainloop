# Chainloop Zero-Day Vulnerability Discovery — Findings Log

Started: 2026-08-03
Branch: `claude/zero-day-vulnerability-discovery-fkwzcn`

## Goal
Discover a chain of vulnerabilities exploitable by a remote user (authenticated or not) enabling:
crash/DoS, RCE, auth bypass, limit/validation bypass, or privilege escalation.

## Method
- First-principles code analysis (NO changelog/git-history/CVE diffing).
- Aggressive multi-agent search (≤6 concurrent), diverse approach families.
- Adversarial double-check on every concrete finding.
- Clone & audit dependencies where the chain may pass through them.

---

## ★ EXECUTIVE SUMMARY — Confirmed findings (ranked by impact)

**Strongest result — a chain that fully breaks intra-org project isolation (both directions):**
Chainloop's project-level RBAC is the security boundary between teams inside one organization. Two independent, multiply-verified authorization gaps defeat it end-to-end:
- **READ:** Finding #2 (CAS cross-project IDOR) — any principal who can read ONE artifact obtains a backend-scoped CAS token that downloads ANY project's artifact (given its digest).
- **WRITE:** Finding #6 (robot-account project-RBAC bypass) — any org member can forge/inject supply-chain attestations into ANY project.
Common root cause: authorization stops at the ORG boundary and treats PROJECT scope as advisory (CAS token carries no project/digest binding; robot-account principals carry no authz subject → project RBAC short-circuits to ALLOW).

| # | Finding | Impact | Confidence | Auth required |
|---|---------|--------|-----------|---------------|
| 12 | Low-priv control-plane SSRF via integration plugins (no allowlist/private-IP guard; in-process); IMDS→cloud-cred theft, response oracle (Discord), attestation/SBOM exfil | HIGH (SSRF→potential infra/credential compromise) | CONFIRMED | any API token / org contributor |
| 2 | CAS download token not digest/project-scoped → cross-project artifact disclosure | HIGH (confidentiality) | CONFIRMED ×2 agents + adversarial | low-priv (read ≥1 artifact) |
| 6 | Robot accounts bypass project RBAC → cross-project attestation forgery (2 variants) | HIGH (integrity/supply-chain) | CONFIRMED ×2 agents | any org member |
| 11 | OIDC identity trust: email-only identity (no `sub`), unverified `preferred_username` preferred over `email` + invitation-hijack (pending invites matched by email, NO org filter, auto-accept at inviter role) → cross-org escalation to admin/owner | HIGH (auth bypass / cross-org priv-esc) | Design flaw + invitation-hijack CONFIRMED (×2 reads); standalone takeover IdP-dependent; email-recycling variant provider-independent | external (IdP-gated) or any org member who can invite |
| 7 | Unrecovered per-request goroutines (dispatcher nil-deref) → full-process crash | MEDIUM (DoS, all tenants) | CONFIRMED latent, race-gated/opportunistic (downgraded by adversarial W2-1) | any org member + own integration |
| 3 | CAS upload digest not verified (S3/Azure/managed) → poisoning/availability | MEDIUM | CONFIRMED | uploader token |
| 8 | CAS default-flag write-skew (no unique index) → org-wide attestation Init DoS | MEDIUM | CONFIRMED | CAS-admin, own org |
| 9 | No finalization guard in Store → integration replay / terminal-state flip | LOW-MED | CONFIRMED | own org |
| 4/10 | referrer.go type-assertion 500 (recovered); attestation-state CAS bypass | LOW | CONFIRMED (bounded) | authenticated |
| 5 | Policy/resource loader SSRF + env:// (CLIENT/CI-side, not control-plane) | MED (CI) | Plausible | contract/group author |

Also confirmed: #12 low-priv control-plane SSRF (integration plugins) — see table; #13 fail-open attestation verification (forgery enabler); #14 forgeable compliance status + premature release-freeze; #8/#9/#10 CAS write-skew / Store replay / attestation-state bypass. All verification threads RESOLVED (no agents pending).
**Honest caps (adversarial):** #6 forgery does NOT bypass a server-enforced gate (all gates client-side); #7 crash is race-gated (opportunistic, not single-shot); #11 standalone takeover is IdP-dependent (invitation-hijack + email-recycling are not).

Notable NEGATIVES (hardened / refuted — don't re-chase): JWT alg/aud confusion; YAML/JSON bombs (yaml.v2 + protojson depth caps); jsonfilter SQLi (anchored allowlist + parameterized); mass-assignment; grpc-web CORS (Bearer-only, no cookie auth); operation-string confusion; DSSE/structpb parse crash (RecursionLimit=10000); cross-tenant secret theft (org-namespaced+random); pprof fallthrough (hardened); managed-backend cross-ORG isolation; referrer graph cross-tenant; released-version immutability; membership double-accept.

---

## Approach Family Registry

| ID | Family | Status | Notes |
|----|--------|--------|-------|
| F1 | Authentication / JWT bypass (multi-provider, federated, alg/aud confusion) | OPEN | attmiddleware.go multi-provider loop |
| F2 | Authorization / RBAC escalation (Casbin, operation authz, membership, groups) | OPEN | |
| F3 | Attestation crafting / material parsing (SBOM/SARIF/VEX/OCI, decompress bombs, path traversal) | OPEN | 25+ material types |
| F4 | CAS / artifact upload-download (bytestream, digest verify, blob managers, SSRF) | OPEN | |
| F5 | Policy engine (OPA/Rego builtins, resource loaders → SSRF/RCE) | OPEN | |
| F6 | Input parsing / mass assignment / proto validation / jsonfilter (SQLi) | OPEN | jsonfilter.go custom |
| F7 | casredirect / referrer (open redirect, SSRF) | OPEN | |
| F8 | Crypto / signing / verification bypass (cosign/sigstore, TSA, digest) | OPEN | |
| F9 | Race conditions / TOCTOU (attestation state, invitations, casbackend) | OPEN | |
| F10 | Org invitation / user-access self-service escalation | OPEN | |
| F11 | Dependency-level bugs (transitive libs invoked with attacker input) | OPEN | |

---

## Findings (concrete)

### ⛔ FINDING #1 — REFUTED (was: YAML alias-bomb DoS)
**Status: FALSE. Do not pursue as-is.** `gopkg.in/yaml.v2 v2.4.0` enforces BOTH mitigations, verified empirically (scratchpad/yamltest/probe):
- alias bomb → `yaml: document contains excessive aliasing` in ~1ms (decode.go:355, CVE-2019-11253 fix).
- deep nesting → `yaml: exceeded max depth of 10000` in ~15ms.
- Go 1.26 `encoding/json` also caps depth (`exceeded max depth`).
My initial "OOM" was a FALSE POSITIVE: `ulimit -v 700000` (700MB virtual) is too low for the Go **runtime's** heap-arena reservation at startup — the OOM was Go starting up, not the bomb. Lesson: build binary first, cap ≥3GB vmem. The `unmarshal`/`IdentifyFormat` pre-authz path is NOT a DoS. (Still worth checking: any code using an OLDER yaml lib, or yaml.v2 streaming `Decoder` in helmchart — see agent F3 claim, likely same mitigation.)

<details><summary>Original (refuted) writeup</summary>

### FINDING #1 [HIGH — CONFIRMED] Remote DoS: YAML alias-bomb crashes whole control-plane, pre-authz
**Family:** F3/F6/F11 (parsing + dependency)
**Impact:** A single tiny (~hundreds of bytes) request from ANY authenticated *user* (any role, no org membership required) crashes the entire multi-tenant control-plane process. Unrecoverable (`fatal error: out of memory`), so `recovery.Recovery()` cannot catch it. Repeatable → persistent DoS for all tenants.

**Chain / data flow:**
1. `craftMiddleware` (grpc.go:221-228): `WithCurrentOrganizationMiddleware` runs BEFORE `WithAuthzMiddleware` in the user-auth selector, and (for user tokens) BEFORE the org-membership check.
2. `WithCurrentOrganizationMiddleware` (currentorganization_middleware.go:82) calls `getFromResource(req)` for `*v1.WorkflowContractServiceCreateRequest` / `UpdateRequest`.
3. `extractOrg` (currentorganization_middleware.go:256) → `unmarshal.IdentifyFormat(rawData)` where `rawData = req.GetRawContract()` (attacker bytes; proto field `raw_contract` has NO max_len — workflow_contract.proto:52,75).
4. `IdentifyFormat` (unmarshal.go:112-125): tries `json.Unmarshal` (fails on YAML → Go 1.26 also caps JSON depth), then **`yaml.Unmarshal(raw, &sink)` into `interface{}`** using `gopkg.in/yaml.v2 v2.4.0`.
5. yaml.v2 has NO alias-expansion limit → a billion-laughs anchor/alias bomb materializes exponentially (e.g. 9 levels × fanout 9 = 387M nodes) → OOM.

**Empirical proof:** `yaml.v2.Unmarshal` of a *few-hundred-byte* bomb (levels=6, fanout=8 = 262k nodes) under a 700MB cap produced `fatal error: out of memory allocating heap arena map` — a runtime throw, not a recoverable panic. (Scratchpad test.) Go 1.26 `encoding/json` DOES cap depth ("exceeded max depth"), so only the YAML path is exploitable.

**Why pre-authz matters:** parse runs in the org-resolution middleware, before `WithAuthzMiddleware` and before `setCurrentMembershipFromOrgName`. Requirement to reach it: a valid *user* JWT (existing account). API-token requests skip this branch (u==nil early return), so it's user-token only — still a trivially low bar in SaaS (any signup).

**Exploit sketch:**
```
POST WorkflowContractService.Create
Authorization: Bearer <any valid user token>
{ "name":"x", "raw_contract": base64(<yaml alias bomb ~300 bytes>) }
```
Bomb payload:
```
a0: &a0 "lol"
a1: &a1 [*a0,*a0,*a0,*a0,*a0,*a0,*a0,*a0,*a0]
... (9 levels) ...
top: *a9
```
→ control-plane OOM-crashes.

**Second instance:** `LoadJSONBytes` (unmarshal.go:128) → `syaml.YAMLToJSON` (sigs.k8s.io/yaml v1.6.0, yaml v2 family) has the same flaw; also the biz/handler-layer contract parse (post-authz). The pre-authz middleware parse is the most accessible.

**What would disprove:** if `getFromResource`/`extractOrg` were actually gated behind authz, or yaml.v2 enforced alias limits (it does not), or a size cap ran before the middleware (MaxRecvMsgSize is multi-MB; bomb is tiny). None hold.

**Open follow-ups:** (a) find any UNAUTHENTICATED endpoint parsing YAML via yaml.v2 / sigs.k8s.io/yaml (would drop the auth requirement entirely); (b) enumerate all yaml.v2/sigs.k8s.io/yaml call sites on attacker-reachable inputs.

</details>

---

### ✅ FINDING #2 [HIGH — CONFIRMED by 2 independent agents + adversarial refutation] CAS download token not digest/project scoped → cross-project artifact disclosure (IDOR)
**Family:** F4. **Source:** F4 + W2-2 (independent verify). **Status: CONFIRMED (cross-project within org). Cross-tenant only under shared-backend misconfig.**
**Airtight evidence (W2-2, read from source):**
- Token Claims = {Role, StoredSecretID, BackendType, MaxBytes, OrgID} — NO digest, NO project (robotaccount/cas/robotaccount.go:38-54). GenerateJWT signs only those (ES512). Validate() checks only audience; CheckRole() only role.
- Mint sites discard req.Digest after using it to find the backend (cascredential.go:156, casredirect.go:129, biz/cascredentials.go:63-74).
- CAS read paths do NO per-digest/project check: HTTP download.go:53-96 (digest from mux.Vars, token from ?t=, only CheckRole+loadBackend); gRPC bytestream.go:172-201 (ResourceName = client digest); **resource.go:43-66 Describe has NO role check at all → metadata oracle (filename+size) for ANY digest even with uploader token.**
- Keys digest-only: s3/backend.go:290-292 `sha256:<d>`, azureblob:93-95 `sha256:<d>`, oci:138-140 `<repo>/<prefix>-sha256:<d>`. s3accesspoint:128-137 `<OrgID>/sha256:<d>` (org-prefixed from TOKEN OrgID → blocks cross-ORG, NOT cross-project). Backends are org-scoped, no project field (schema/casbackend.go).
- Control-plane `/download/{digest}` (casredirect HTTPDownload) DOES re-authorize the specific digest (safe) BUT embeds the same generic token in the redirect → replayable against CAS with a different digest.
**Exploit:** (1) mint downloader token by presenting a digest you can read (CASCredentialsService.Get or grab ?t= from any download); (2) replay `GET https://cas/download/sha256:<VICTIM_PROJECT_DIGEST>?t=<TOKEN>` within 30s → get victim project's blob (checksum-verified against REQUESTED digest). gRPC ByteStream.Read / Resource.Describe equivalents.
**Blast radius:** cross-project within org CONFIRMED (defeats project-RBAC artifact confidentiality). Cross-tenant REFUTED normally (per-org backend secret, ES512 asymmetric, s3accesspoint org-STS); only shared-backend self-managed misconfig.
**Limits:** 30s TTL (doesn't stop active scripted attacker), must know target digest (256-bit hash, but often non-secret: CI logs, image manifests, git SHAs). No strong API discovery primitive (referrer is scoped). Weak oracles: ReferrerRepo.Exist (data/referrer.go:126-142) NOT org-scoped → boolean cross-org existence oracle for ATTESTATION digests (internal push path only); CAS Describe metadata oracle.
**Fix:** add digest claim to token + enforce claims.Digest==requestedDigest in CAS read paths, or re-authorize (org,project,digest) at CAS; add role check to Resource.Describe; org-scope ReferrerRepo.Exist.
**ROOT-AGENT FINAL CONFIRM (3rd independent read of the actual sink):** download.go:53-135 — digest from URL path (line 63); token = {Role,BackendType,StoredSecretID,OrgID,MaxBytes}, NO digest; sole gate `CheckRole(Downloader)` (line 76); downloads the REQUESTED digest (line 119); checksum (line 130) verifies content vs REQUESTED digest = integrity, NOT authorization. No org/project/digest binding check anywhere. **Privilege floor:** DefaultAuthzPolicies (apitoken.go:117) grants project-scoped tokens `PolicyArtifactDownload` → any org member can mint such a token and obtain a downloader token that reads the whole org backend keyspace. (apitoken.go:120 also grants `PolicyRobotAccountCreate` → confirms Finding #6 Variant A floor.)

<details><summary>(original agent-reported summary)</summary>
**Family:** F4. **Source:** F4 agent. **Status: verifying.**
The CAS access token (ES512 JWT minted by control-plane) carries `{Role, StoredSecretID, BackendType, MaxBytes, OrgID}` — **no digest, no project**. Per-digest/project authz is enforced ONLY at token-issuance time (control-plane cas-mapping lookup). The CAS service then serves ANY digest presented to a valid-role token. All projects in an org share the org's default backend; objects keyed purely by digest (S3/Azure `sha256:<digest>`, OCI `chainloop-<digest>`).
**Exploit:** contributor/project-scoped-token with access to ONE artifact in project P1 obtains a downloader token, then `GET /download/sha256:<D2>?t=<token>` for a digest D2 in project P2 they can't access → receives it. Token validated independently of URL path (jwt.go), digest re-read from mux.Vars (download.go:63). Editing the path while keeping `t` downloads a different blob.
**Limits:** attacker must KNOW target digest (content hash; not secret but discovery is project-scoped). Managed s3accesspoint blocks cross-ORG (org-prefixed keys) but NOT cross-PROJECT. 30s token expiry doesn't help (unlimited reqs in-window + re-mint).
**Cited code:** cascredential.go:104-156, casredirect.go:82-137, bytestream.go:184-201, download.go:63-119, jwt.go:41-47, data/casmapping.go:108-120.
</details>

### FINDING #3 [MEDIUM — agent-reported] CAS upload digest not verified vs content (S3/Azure/managed) → poisoning/DoS
**Family:** F4. `bytestream.Write` stores claimed digest without hashing content; only OCI backend validates. S3 checksum enforcement commented out (s3/backend.go:167-170). Dedup `Exists` short-circuit → pre-seed `sha256:D` with garbage → victim's later real upload of D silently dropped → downloads fail checksum gate permanently. Integrity/availability (download-side hash check prevents forgery-as-authentic). Cross-project within org.

### W2-6 (DSSE/in-toto library depth) — RESULTS
- **Bundle-parse stack-overflow crash: REFUTED (empirical).** protojson `RecursionLimit=10000` → deeply nested JSON returns `proto: exceeded max recursion depth`, no stack overflow (verified with exact go.mod versions). structpb AsMap, encoding/json also capped. No OOM (bounded by 4MB MaxRecvMsgSize). ~10000-deep JSON is only ~60-80KB and harmless.
- **referrer.go:398/400 type-assertion (Finding #4): confirmed RECOVERABLE** (synchronous ExtractAndPersist path → recovery middleware → 500 + Sentry; NOT on a goroutine path → cannot become a crash). material.Hash==nil nil-deref is SAFE (normalizeMaterial requires digest before UploadedToCAS).
- **Minor:** statement payload protojson-unmarshalled 4-6× per Store → CPU/alloc amplification (bounded, no crash).
- **Does NOT contradict Finding #7:** dispatcher.go:136 `*wfRun.FinishedAt` nil-deref executes BEFORE loadInputs material parsing, and is about run metadata not the bundle.

### FINDING #4 [LOW-MED — agent-reported] Server-side panic via unchecked type assertions on attestation subject annotations
**Family:** F3. `biz/referrer.go:398,400`: `materialType = v.(string)` / `uploadedToCAS = v.(bool)` on client-controlled in-toto subject `Annotations.AsMap()`. Push a bundle with `annotations:{"chainloop.material.type":123}` → panic. REACHABLE server-side (AttestationService.Store, no signature verification before parse, bundle is opaque bytes not protovalidated). BUT recovery.Recovery() catches → per-request 500 + Sentry spam, not a process crash. Sibling v02.go uses panic-safe getters — confirms it's a bug. Lead: hunt for the same pattern in an UNRECOVERED goroutine (F3 flagged dispatcher.go:270-276 casClient.Download in unrecovered goroutine).

### W2-5 (transport/grpc-web/CORS) — RESULTS (mostly SAFE)
- **Permissive CORS (WithOriginFunc→true) + AllowCredentials: NOT exploitable.** Auth is 100% Bearer JWT (gRPC metadata / ?t= / localStorage), NEVER cookie (only cookies are transient OIDC-dance: oauthState/callback/longLived, SameSite=Lax/Secure/HttpOnly in prod). Cross-origin page can't supply victim's token → state-changing RPCs fail closed. Only 3 public methods readable cross-origin (already public).
- **Operation-string manipulation: IMPOSSIBLE** (kratos uses info.FullMethod from grpc-go registry, resolved before interceptor; transcoded HTTP sets hardcoded operation constant). grpc-web uses same processUnaryRPC → middleware runs identically.
- **Unanchored regexes:** enumerated all 84 methods — only StatusService/Infoz,Statusz + SigningService/GetTrustedRoot skip all auth, all intentionally public. No sensitive method exposed. Latent/fragile (future SigningService method auto-public). `fullyConfiguredCASBackendRequireRegexp` uses `.` where `/` meant (works only because regex `.` matches `/`). Not exploitable now.
- **[LOW/deployment] pprof unauth on 0.0.0.0:6060** IF `enable_profiler`=true (opt-in; default off but config.devel.yaml sets true) → heap/cmdline/profile leak (JWTs/secrets in memory). Network-level mitigation only. Main API listener correctly hardened.
- Prometheus revocation gap (dup of F1). Chainloop-Organization header: membership always re-verified (no confusion). Framing/OOM bounded. grpc-web websockets disabled. AuthFromQueryParam unused in CP.

### FINDING #5 [MED — agent-reported, CLIENT-side] Policy/resource loader SSRF + file/env read
**Family:** F5/F3. `pkg/policies/loader.go:141` http.Get(ref), `:115` os.ReadFile; `group_loader.go`; `policies.go:1129+` cosign `LoadFileOrURL` supports `env://VAR` (env exfil) + http + file. Driven by workflow-contract / policy-group `ref`/`path`. Blind SSRF from CI runner (IMDS 169.254.169.254, internal svcs), file existence oracle, env read. Client/CI-side (not control-plane). `resourceloader.go` also unhardened (http.Get, env://, no timeout/allowlist) but operator-driven. Egress allowlist for http.send is admin-controlled (can't self-add exfil host).

### ✅ FINDING #6 [HIGH — CONFIRMED by 2 independent agents (F2+W2-3)] Cross-project priv-esc: robot accounts bypass project RBAC (evidence forgery)
**Family:** F2. **Status: CONFIRMED. Two variants, same root cause.**
**ROOT CAUSE:** robot-account principals carry NO authz subject → `rbacEnabled(ctx)`=false (service.go:392-402; authz.go:33-35) → the project-RBAC check `userHasPermissionOnProject` short-circuits ALLOW (service.go:267) on the ENTIRE attestation path (Init/Store/Cancel).
**Variant A (front-door, RobotAccountService.Create missing project scope):** `RobotAccountService.Create` (robotaccount.go:41-59) passes attacker `req.WorkflowId` to biz `Create` which only checks workflow∈ORG (biz/robotaccount.go:78 GetOrgScoped), no project check. A project-scoped API token carries `PolicyRobotAccountCreate` (DefaultAuthzPolicies apitoken.go:120; ServerOperationsMap authz.go:391) → middleware authorizes by ACL only (no project scope at that layer). So a project-X token creates a robot account bound to project-Y workflow → gets JWT → pushes forged attestations to Y.
**Variant B (back-door, STRONGER — robot account not workflow-bound on USE):** `robotAccount.WorkflowID` is NEVER compared to the request-targeted workflow; the only binding check (attestation.go:735-736) is gated on `CurrentAPIToken(ctx)` which is nil for robot accounts. So ANY robot account can Init/Store/Cancel against ANY workflow in its org BY NAME. Attacker mints a robot account for their OWN project-X workflow (fully legit), then `Init{projectName:Y, workflowName:Y-wf}` → run created in Y → `Store` forged attestation. Drops the target-UUID precondition (only target names needed).
**Min preconditions:** any org member (can create own project → become ProjectAdmin → mint project token). Amplification: the project token gains PolicyRobotAccountCreate that the minter's own org role lacks. Knowledge of target project+workflow NAMES (non-secret, in dashboards/CI logs/run URLs).
**Impact:** cross-project forgery/injection of supply-chain attestations (fake "passing" evidence for a vulnerable artifact; evidence-store pollution) into a project the attacker has no rights to. Org boundary holds (no cross-tenant). Authenticated insider.
**Same-class hunt (W2-3):** all OTHER DefaultAuthzPolicies RPCs DO re-check project scope; RobotAccount.Create is the sole front-door gap. (Also: IntegrationsService Register/List/Describe are org-wide → project token can enumerate org integrations — over-broad, lower sev.)
**Fix:** (a) scope RobotAccountService.Create to caller's project; (b) enforce robotAccount.WorkflowID against resolved workflow in findWorkflowFromTokenOrNameOrRunID.

### ⚠️ FINDING #7 [MEDIUM — CONFIRMED latent, race-gated (DOWNGRADED by W2-1 adversarial)] Unrecovered dispatcher goroutine nil-deref → process crash (opportunistic multi-tenant DoS)
**Family:** F9/crash. **Status: real latent crash; Plausible/opportunistic-under-load, NOT a deterministic single-shot.**
**W2-1 CORRECTION (rigorous):** The `*wfRun.FinishedAt` nil-deref (dispatcher.go:136) in the unrecovered goroutine is REAL, but the race is **defender-favored**: the dispatcher does ~4 DB round-trips + a secret read (initDispatchQueue: ListAttachments + FindByIDInOrg [+ ReadCredentials], loadInputs, FindByID) BEFORE the deref at dispatcher.go:118/136, while the main goroutine reaches MarkAsFinished (attestation.go:403) after ~0-1 ops → MarkAsFinished reliably commits `finished_at` FIRST → dispatcher reads non-nil → no crash. So it fires only under adverse scheduling / DB-pool contention (a high-volume attacker firing many concurrent Stores can partly self-induce). The "guaranteed if MarkAsFinished skipped" escalation (W2-4) is **NOT attacker-forceable**: the only code between spawn and MarkAsFinished is the markAsReleased block; UpdateReleaseStatus won't fail on a valid version UUID and ProjectVersion is never nil. Also F6's other claims were WRONG: `wfRun.Attestation.Digest` (dispatcher.go:139) is NEVER nil (entWrToBizWr:583 always inits Attestation); `*wfRun.CreatedAt` safe. So FinishedAt is the ONLY nil-able deref.
**Still valid & worth reporting:** the SYSTEMIC issue is real — 3 per-request goroutines (attestation.go:350 CAS-upload, :384 dispatcher, dispatcher.go:146 per-plugin) have NO recover(), so ANY panic in them crashes the whole multi-tenant process (recovery.Recovery only wraps the sync handler). Precondition for the FinishedAt path: ≥1 integration attached to attacker's own workflow. Impact if it fires: full process crash, all tenants.
**Fix:** add recover() to the 3 goroutines; nil-guard dispatcher.go:135-136; set FinishedAt before dispatch.
<details><summary>(superseded HIGH writeup)</summary>
**Family:** F9/crash. **Status: CONFIRMED reachable (deterministic via one path); race otherwise.**
`storeAttestation` launches the integration dispatcher as a bare `go func(){ ... }()` with context.TODO() and NO recover() (attestation.go:384), BEFORE `MarkAsFinished` (attestation.go:403). Inside, dispatcher.go:136 does `FinishedAt: *wfRun.FinishedAt` — UNCONDITIONAL deref; `FinishedAt` is nil for a run not yet finalized (schema Optional; toTimePtr→nil). (dispatcher.go:139 `wfRun.Attestation.Digest` is a second nil-deref candidate; line 146 spawns further bare goroutines.) A panic in a detached goroutine is NOT caught by recovery.Recovery() (which only wraps the request goroutine) → **entire control-plane process aborts → ALL tenants down.** Independently confirmed the deref site by reading dispatcher.go:108-147.
**Precondition:** ≥1 fan-out integration attached to the attacker's own workflow (else dispatcher returns early at len(queue)==0). Attacker controls this in their own org.
**Reachability:**
- **Race path:** dispatcher's GetByIDInOrg SELECT (dispatcher.go:118) wins vs MarkAsFinished commit (attestation.go:403). Attacker widens the window with MarkVersionAsReleased=true (inserts UpdateReleaseStatus tx between :384 and :403) + a fast no-secret/no-downloadable-material integration + concurrent flooding. One win crashes the shared process.
- **GUARANTEED path (W2-4):** any error on the main path between goroutine launch (:384) and MarkAsFinished (:403) makes MarkAsFinished never run → FinishedAt stays nil → dispatcher ALWAYS crashes. (Open: can attacker force UpdateReleaseStatus to fail deterministically? W2-1 investigating.)
**Fix:** nil-guard dispatcher.go:135-139; call MarkAsFinished before launching dispatcher; add recover() to detached goroutines.
</details>

<details><summary>(#6 pre-verification note)</summary>
**Family:** F2. **Status: W2-3 verifying.**
`RobotAccountService.Create` (robotaccount.go:41-59) takes attacker `req.WorkflowId`; biz `Create` (biz/robotaccount.go:63-105) only checks workflow∈ORG (GetOrgScoped), NOT caller's project. A project-scoped API token carries `PolicyRobotAccountCreate` (DefaultAuthzPolicies, apitoken.go:~120) → authz middleware lets project-X token hit /RobotAccountService/Create. Robot-account JWTs carry NO authz subject → on AttestationService.Init/Store, `rbacEnabled(ctx)`=false → `userHasPermissionOnProject` short-circuits ALLOW (service.go:266-269,192-194).
**Escalation:** principal scoped to project X → create robot account bound to project-Y workflow → push forged attestations to project Y (evidence forgery). viewer→attestation-writer cross-project.
**Preconditions:** attacker holds project-admin on some X (to mint token) + knows a workflow UUID in Y. Per F2, realistic if attacker has any read on Y.
**Same-class hunt (W2-3):** enumerate all RPCs reachable by project-scoped tokens lacking project re-check.
**Latent note (F2):** service.go:351-352 checkPolicy hardcodes PolicyOrganizationCreate instead of param (harmless today). IsAdmin() bypass in middleware.go:65 backstopped by service-layer owner re-checks — fragile.
</details>

### FINDING #13 [MED — CONFIRMED (W3-3)] Fail-open attestation signature verification (forgery enabler for #6)
`WorkflowRunUseCase.SaveAttestation` → `verifyBundle` (workflowrun.go:464-476, 583-610) is the ONLY server-side bundle verification, and it FAILS OPEN: returns nil (skip) if `GetTrustedRoot`==ErrNotImplemented (no signing backend configured) OR `VerifyBundle`==ErrMissingVerificationMaterial (bundle has no cert AND no public key — verifier.go:80-82). So an attacker submits a bundle with NO verification material → verification silently skipped → attestation stored/indexed as authoritative. Even when it runs+passes, it only proves "some chainloop cert signed this envelope" — NOT bound to the target project/workflow. This is the enabling weakness behind #6's forgery. Fix: fail closed when a signing backend is configured; bind signer identity to the target org/project.

### FINDING #14 [MED — CONFIRMED (W3-3)] Forgeable compliance status + premature release-freeze (integrity/DoS)
Server persists policy PASSED/violations status DERIVED FROM UNVERIFIED predicate content (workflowrun.go:504-507; client-set fields v02.go:262-289) and displays it in UI/API/filters — the actual block gate (`BlockOnPolicyViolation`) is CLIENT-side only (crafter.go:785+, cli push). So forged attestations show "PASSED"/no-violations (misleading compliance signal). Separately, `req.MarkVersionAsReleased` (a request bool, NOT content, NOT gated on policy pass; attestation.go:396-401 → projectversion.go:139-150) flips a version to `released`; if org has `BlockAttestationsOnReleasedVersions`, further attestations are rejected (data/workflowrun.go:303-325) → attacker can **prematurely FREEZE a victim's version** with forged content (integrity/DoS + misleading release marker).

### W3-3 BOUNDING NEGATIVE (caps #6 severity — honest): The control-plane enforces NO server-side security gate that trusts attestation content. All policy/compliance gates are CLIENT-side; referrer graph is discovery-only + RBAC-scoped at read (no authz decision); CAS mappings are content-addressed + org/project-scoped (poisoned mapping can't serve DIFFERENT content for a digest, no cross-tenant read); materials parsed for indexing/fan-out only, not decisions. So #6 forgery blast radius = evidence-store pollution + misleading compliance/release UI + downstream-integration (own-org) pollution, until a client verifies at read time. It does NOT clear a server-enforced control. (Confirms #6's RBAC-skip mechanism: service.go:392-402, 267-269.)

### FINDING #8 [MED — CONFIRMED (W2-4)] CAS default/fallback/inline flag write-skew → org-wide attestation Init DoS
No partial unique index for "one default backend per org"; invariant enforced by clear-then-set in app code (data/casbackend.go:145-178, 205-266). Under READ COMMITTED, two concurrent Create/Update(default=true) write-skew → two defaults. FindDefaultBackend uses `.Only()` (data/casbackend.go:71) → "not singular" error → every attestation Init for that org fails (attestation.go:188) until admin fixes. Same-org availability; needs CAS-admin. Fix: partial unique index `WHERE default=true` per org.

### FINDING #9 [LOW-MED — CONFIRMED (W2-4)] No finalization guard in Store → replay/terminal-state flip
Store/storeAttestation/MarkAsFinished (attestation.go:244-285; data/workflowrun.go:419-433) never check run state before writing — no state-machine guard/lock. Attacker (own org) can re-Store a finished run → re-trigger all fan-out integrations (replay/amplification) and re-flip terminal state; race Store(success) vs Cancel(canceled) → last-writer-wins. (attestations unique index prevents dup bundle row, but dispatch + finalize unguarded.) Fix: guarded transition `WHERE state='initialized'`.

### FINDING #10 [LOW — CONFIRMED (W2-4)] Attestation-state optimistic-concurrency bypass via empty baseDigest
AttestationStateRepo.Save only does the digest CAS + ForUpdate when baseDigest != "" (data/attestationstate.go:70-88; code TODO "make digest check mandatory"). Client omitting base_digest → blind last-writer-wins overwrite of that run's crafting state. Per-run, same-tenant. Fix: mandatory digest check.

### W3-2b (caching) — RESULTS (mostly SAFE; one LOW)
- **[LOW] Membership-revocation lag (Finding-cache-1):** memberships cache (key=user.ID, in-memory per-replica, **TTL=1s**, wire.go:157) is NOT invalidated on UpdateRole/DeleteMembership/Leave/org-delete (no biz-layer path holds a cache ref; only an unrelated Purge at attestation.go:855). So a revoked role/admin persists ≤~1s PER REPLICA. LRU TTL is fixed-from-insert (reads don't extend; verified in golang-lru source) → strictly ≤1s. LOW (1s too short to weaponize); latent risk = safety rests on one un-guarded TTL constant, and key=user.ID spans all orgs+instance-admin. Org SUSPENSION is NOT cached (enforced fresh from DB → immediate).
- **[latent, not exploitable] Claims-cache non-injective key:** `fmt.Sprintf("%s:%s", jwtToken, orgName)` (attmiddleware.go:353), both attacker-controlled and may contain `:` → ("X","Y:Z") and ("X:Y","Z") collide. But cross-principal read needs the victim's secret bearer token as prefix (dead end); value only cached after upstream 200 for that exact token; reading another's claims = de-escalation. TTL 10s. Plausible defect, Unlikely exploit. Fix: hash/length-prefix parts.
- **SAFE:** sanitizeKey = base64.RawURLEncoding (injective, no truncation; NATS key regex rejects invalid → miss not collision) and MOOT for auth caches (in-memory, don't use it). Fail-open is fail-CLOSED (empty membership → Forbidden; cache error → DB; no default-allow). Bundle caches content-addressed (no cross-tenant). Minor: in-memory backend returns shared pointer (safe today, read-only).

### W2-4 race NEGATIVES (SAFE): org/workflow/project/contract/integration/apitoken name uniqueness (partial unique indexes); membership double-accept (unique index + idempotent AddResourceRole); released-version immutability (SELECT FOR UPDATE, done right); run/version counters (atomic col=col+1 SQL); apitoken policies JSON (write-once).

### FINDING #11 [HIGH if exploitable — CONFIRMED design flaw (mine); IdP-dependent] OIDC account takeover: `preferred_username` (unverified) preferred over `email`, no email_verified check
**Family:** F1/auth. **Status: takeover mechanism CONFIRMED by my read; SSO-group-escalation REFUTED; invitation-hijack + IdP-dependency → W3-1b.**
**My confirmations (read directly):** (1) UpsertByEmail (user.go:157-208) lowercases email, `FindByEmail` → if a user with that email EXISTS returns it (LOGIN path) ⇒ **takeover of that existing account**; else CreateByEmail (squatting). Identity key = email ONLY, no OIDC `sub` binding. (2) `SSOGroups` (user.go:184,195) flows ONLY into auditor events (UserSignedUp/LoggedIn) — NOT authorization ⇒ **SSO-group→role escalation REFUTED**.

**W3-1b — CONFIRMED, with a concrete cross-org privilege-escalation sub-chain:**
- **Design flaws (unconditional, in-code):** claims struct (auth.go:336-346) has NO EmailVerified and NO Sub field (never decoded); verifier (oidcauthenticator/auth.go:56-66) checks sig/issuer/aud/exp only, not email_verified; preferredEmail prefers preferred_username over email; identity = email string only, one global user table (same email from ANY IdP/connection → same account). `?connection` is explicitly forwarded (auth.go:319) → multi-connection Auth0 is an intended deployment.
- **★ Invitation-hijack chain (CONFIRMED priv-esc):** `AcceptPendingInvitations(u.Email)` (auth.go:401) → `PendingInvitations(receiverEmail)` (data/orginvitation.go:87-105) matches receiver_email exactly with **NO org filter** → returns pending invites across EVERY org → auto-creates membership at the **inviter-chosen role (up to owner/admin), no re-consent** (orginvitation.go:298-303), which becomes the live casbin subject (currentorganization_middleware.go:217). So: a member of Org X invites victim@corp.com at admin/owner (normal onboarding) → attacker logs in controlling that email → auto-joins Org X as admin/owner BEFORE the real victim. Cross-org escalation to admin/owner.
- **Provider-independent variant (no malicious IdP):** email recycling/reassignment at any IdP → old user's account + all memberships transfer to the new holder (because no sub binding).
- **IdP dependency (honest):** standalone takeover NOT exploitable vs Google (verified/immutable email, no preferred_username); exploitable vs self-service Keycloak / unverified-email Auth0 DB / Dex connectors / generic OIDC; Entra usually protected (admin-controlled UPN). Chainloop is built to federate arbitrary customer OIDC → meaningful share exposed.
- **Adversarial refutation:** case-folding does NOT block (ToLower→exact match works); whitespace/display-name variants ("victim@x.com ", "<victim@x.com>") do NOT match (raw string used, not parsed .Address) → those are look-alike squatting only, not exact takeover (genuine partial refutation). No trimming/unicode normalization (hardening gap, doesn't aid ASCII-victim takeover). CSRF state irrelevant (attacker auths own session).
- **Rating: HIGH severity; exploitability = CONFIRMED for invitation-hijack + email-recycling; Medium-conditional (IdP-dependent) for arbitrary standalone takeover.**
**Fix:** require & verify `email_verified`; bind identity to issuer+`sub` (not email); don't prefer preferred_username; org-scope/re-consent invitation acceptance; trim/normalize email.
`preferredEmail()` (auth.go:350-359): if `preferred_username` claim parses as an email, it is used as the account identity IN PREFERENCE to the `email` claim; else falls back to `email`. Then `UpsertByEmail(preferredEmail())` (auth.go:390) matches/creates the Chainloop user by that string. NO `email_verified` check anywhere (struct auth.go:336-346 has no such field). `preferred_username` is a well-known MUTABLE/UNVERIFIED OIDC claim (spec: "not guaranteed to be unique"; the code comment even notes Entra "might show a proxy email" / "might be a phone or username").
**Exploit (IdP-config dependent):** if the configured IdP lets a user set `preferred_username` to an arbitrary email (self-service profile, Keycloak/Auth0/Dex connectors, some Entra setups), attacker sets it to `victim@company.com`, logs in → `UpsertByEmail` matches victim's existing account → **full account takeover** (or pre-registration squatting if not yet existing). Auth bypass — top of impact hierarchy.
**Also:** `SSOGroups: claims.Groups` (auth.go:393) — if the `groups` OIDC claim drives org membership/role (SSO group→role mapping), and groups is attacker-influenceable at the IdP, that's a separate priv-esc. W3-1 to check the SSOGroups consumer.
**Honest dependency:** exploitability hinges on the IdP allowing user-controlled preferred_username/groups (like F1's federated finding). But the DESIGN FLAW (trusting unverified claim, preferring preferred_username over email, no email_verified gate) is Confirmed in-code.

### ✅ FINDING #12 [HIGH — CONFIRMED (W2-7b)] Low-privilege control-plane SSRF via integration plugins (+ IMDS credential-theft potential, response oracle, data exfil)
**Family:** F7/SSRF (server-side). **Status: CONFIRMED, low-priv.**
**Privilege floor (the key):** `DefaultAuthzPolicies` grants API tokens `PolicyRegisteredIntegrationAdd` (apitoken.go:127) + `PolicyAttachedIntegrationAttach` (apitoken.go:129). `PolicyRegisteredIntegrationAdd` is in NO role in RolesMap → integration Register is reachable by **any default API token** (standard CI credential) or org Admin/Owner. `IntegrationsService.Register` has NO per-resource authz (integration.go:79-83, only requireCurrentOrg). Attach is even lower (RoleOrgContributor/RoleProjectAdmin/token, authz.go:285,335).
**No SSRF guard anywhere** (grep 169.254/IsPrivate/Loopback/allowlist = none). Core plugins run **IN-PROCESS** in the control plane (plugins/plugins.go:68-78); dispatcher calls plugin.Execute directly.
**Confirmed sinks (arbitrary attacker host, fired at Register AND Execute):**
- **Webhook** (webhook.go:245 POST via testWebhookURL:117 + Execute:198/219): only guard = http/https scheme (validateURL:305). Response body returned in error (semi-oracle). Execute exfiltrates full attestation envelope + CycloneDX/SPDX SBOM.
- **Discord** (discord.go:92 `http.Get(WebhookURL)` at Register): **NO validation at all**; response JSON name/username decoded into stored config (discord.go:101-111) → returned via DescribeRegistration ⇒ **strong read oracle** of the internal endpoint's response.
- **Slack** (slack_webhook.go:142 `http.Post`): no validation; response body in error (semi-oracle).
- **Dependency-Track** (client/sbom.go:214/278/314): Location=InstanceURI, only url.ParseRequestURI (no host restriction); **Attach re-hits host** at lower priv; Execute exfiltrates CycloneDX SBOM.
- **SMTP** (extension.go:205 SendMail host:port): host+port fully user-controlled, no validation → internal TCP connect / port-probe oracle.
**Impact:** control-plane → arbitrary internal host (169.254.169.254 cloud IMDS → **steal control-plane cloud/IAM credentials** → potential infra/cross-tenant compromise; Vault localhost:8200; internal services), with response oracles (Discord/webhook/slack) and exfil of other-tenant... no, own-org attestation+SBOM to attacker endpoint. Reachable by the standard CI token — LOW privilege.
**Fix:** shared egress allowlist / private-IP + link-local blocker applied before every plugin Register/Attach/Execute outbound call and every CAS ValidateAndExtractCredentials.

### FINDING #12b [MED — CONFIRMED (W2-7b), admin-gated] Control-plane SSRF via CAS backend Location (S3/OCI/Azure custom endpoint)
`CASBackendService.Create/Update` → `ValidateAndExtractCredentials(req.Location,...)` (casbackend.go:87/133) synchronously, + Revalidate → PerformValidation (casbackend.go:886). S3 backend.go:88 sets BaseEndpoint=endpoint, CheckWritePermissions does PutObject/GetObject (s3/backend.go:251-266); Location parsed as `http://host/bucket` → arbitrary host incl. `http://169.254.169.254/bucket` (SigV4 PUT+GET; Create/Update returns validation error = oracle). OCI: remote.CheckPushPermission (oci/backend.go:296) → arbitrary registry host:port over HTTPS. Azure: constrained (needs valid AAD creds first). **Gated by PolicyCASBackendCreate/Update (authz.go:374) = org-admin/instance-admin only, NOT in API-token defaults** → lower priority than #12.
**W2-7b NEGATIVES:** OIDC/JWKS uses server-config Domain (not per-tenant). Policy provider resolution: p.url is server config, tenant name is JoinPath-escaped path suffix (can't alter host/scheme) — server-side raw-URL policy fetch is CLI-only (confirms F5). Guac: exfil to attacker GCS bucket (external, not internal SSRF).

### Agent NEGATIVE results (ruled out, don't re-run without new mechanism)
- Policy Rego/WASM eval is CLIENT-side only; control-plane never evaluates untrusted Rego → no server RCE/SSRF via policy code. Rego sandbox strips dangerous builtins; http.send gated by admin allowlist. WASM FS-sandboxed + 5s cap.
- CAS: managed s3accesspoint cross-ORG isolation solid; referrer graph re-checks org+project visibility per level (no cross-tenant); download content hash-verified; JWT ES512 pinned, no alg-confusion.
- Material parsers: no XXE (Go encoding/xml ignores DTD ents); zip-slip blocked by archiveio.safePath; no exec.Command RCE; attestationstate bounded+panic-free.
- Policy-provider resolution is name-based from server allowlist, not arbitrary-host SSRF.

---

## Reference: gRPC middleware auth map (grpc.go:104-320)

Security-critical **unanchored** regexes gate which middleware runs:
- `currentUserSkipRegexp` = AttestationService/.*, StatusService/.*, AttestationStateService, SigningService → these SKIP the user-auth branch.
- `robotAccountRequireRegexp` = AttestationService/.*, AttestationStateService/.*, SigningService/GenerateSigningCert → these REQUIRE robot-account (multi-provider JWT) auth.
- `allButOrganizationOperationsSkipRegexp` = OrganizationService/Create, UserService/ListMemberships, ContextService/Current, AuthService/DeleteAccount → these SKIP org+suspension+**authz** middleware.
- `fullyConfiguredOrgSkipRegexp`, `fullyConfiguredCASBackendRequireRegexp`, `allowListSkipRegexp` gate other checks.

RULED OUT (independently): SigningService asymmetry — `GetTrustedRoot` skips both user & robot auth, but it is intentionally public (returns trust root/public keys). Not sensitive.
NOTE for agents: regexes are unanchored (no ^$). gRPC operation strings are fixed method names so not directly injectable, BUT worth checking HTTP-gateway path/operation confusion and whether any sensitive method name is a substring/superstring collision.

HTTP raw routes that DO NOT run kratos middleware (http.go:69-96): AuthLoginPath, AuthCallbackPath, PrometheusMetricsPath (self-auth via AuthFromAuthorizationHeader). Raw routes `/download/{digest}` (CASRedirectSvc.HTTPDownload), `/openapi.yaml`, referrer HTTP server — verify auth posture.
pprof: hardened (dedicated opt-in :6060 + hardenedRouteOptions prevents DefaultServeMux fallthrough). RULED OUT.

---

## Wave Log

### Wave 1 — COMPLETE (F1,F3,F4,F5,F6 reported; F2 still running)
Diverse portfolio across F1–F10. Key outcomes:
- F1 (auth): no drop-in unauth bypass. Federated-orgId trust (cond.), empty-secret guard, prom revocation gap. All low/conditional.
- F3 (materials): server-side referrer.go panic (recovered); material bombs are CLIENT-side only (server doesn't import crafter/materials).
- F4 (CAS): **download-token IDOR (HIGH)**; upload poisoning (MED).
- F5 (policy): eval is client-side only; loader SSRF client-side.
- F6 (jsonfilter): parser hardened (no SQLi). **KEY: recovery.Recovery() does NOT wrap spawned goroutines → unrecovered goroutine panic = full crash.**

### ★ HOT THREADS for Wave 2
1. **Unrecovered-goroutine crash** (F6+F3+F1 converge): find attacker-controlled deterministic panic inside a handler-spawned goroutine (attestation.go Store: CAS-upload + dispatcher goroutines process non-sig-verified in-toto content) → full control-plane DoS. HIGHEST VALUE.
2. **CAS download IDOR** (F4): verify + weaponize + max blast radius.

### Root-agent independent negatives (ruled out, not overlapping agents)
- **Cross-tenant secret theft via CAS SecretName**: RULED OUT. Vault path = `prefix/orgID/uuid.Generate()` (credentials/vault/keyval.go:148), org-namespaced + random; read via signed ES512 token; not attacker-influenceable.
- **Template injection (pkg/templates ApplyBinding)**: RULED OUT server-side. Only called in pkg/policies (client-side only); text/template with NO FuncMap → no RCE; data limited to bindings map.
- **Auto-onboarding org membership**: config-driven (admin OnboardingSpec), not attacker-controlled. Intended.
- **Group service authz**: quick scan — mutating methods (AddMember/RemoveMember/UpdateMemberMaintainerStatus) each call group-scoped permission check before mutating, scope by currentOrg. No obvious gap (matches F2).
- **pprof / JSON depth (Go 1.26) / yaml.v2 bombs**: all mitigated (see Finding #1 refutation + pprof hardening).

### Wave 3 — COMPLETE (W3-1b OIDC, W2-7b SSRF, W3-2b caching, W3-3 attestation-trust)
All confirmed/refuted as recorded. FINAL: 5 HIGH (SSRF #12, CAS-IDOR #2, robot-RBAC #6, OIDC/invite-hijack #11 [IdP/invite-dependent], + verification fail-open #13 supporting #6), 1 MED-DoS (#7 race-gated), plus mediums #3/#8/#9/#12b/#14 and lows #4/#10/#5/prometheus/pprof/cache-revocation. Extensive verified negatives. Session-limit hit mid-Wave-3; failed agents retried successfully.

### Wave 2 — launching
W2-1 crash-thread (goroutine panics), W2-2 CAS IDOR adversarial verify, W2-3 races/TOCTOU (F9), W2-4 grpc-web/CORS/HTTP-transcode/bytestream, W2-5 server-side DSSE/in-toto/proto-Struct library parsing bugs. (F2 RBAC still running.)
NOTE to all: yaml.v2 v2.4.0 is DoS-protected (excessive-aliasing + max-depth); don't re-derive billion-laughs on it.
