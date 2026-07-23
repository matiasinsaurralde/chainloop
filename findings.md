# Security Hunt Findings

Variant hunt against `chainloop` at HEAD (branch `claude/security-vulnerability-hunt-i1cfw6`).
Each finding was traced from attacker-controlled input to sink and adversarially
falsified before inclusion.

| # | Title | Class / CWE | Severity | Boundary crossed |
|---|-------|-------------|----------|------------------|
| 1 | Cross-project artifact download via project-scoped API token | AuthZ bypass / CWE-863 | High | project → project (same org) |
| 2 | Unbounded `APITokenService/List` query | DoS / CWE-770 | Medium | same org |
| 3 | Org-viewer can hold group-maintainer (Lead 18 regression) | Missing authz / CWE-269 | Medium | role cap (same org) |

> Note on scope: all three are **intra-organization**. No verified
> cross-organization (org A → org B) exfiltration was found; see the
> "Cross-tenant isolation review" section at the end.

---

## Finding 1 — Cross-project artifact download via project-scoped API token

- **Class / CWE / Severity:** Authorization bypass / CWE-863 / **High**
- **Sink:** `app/controlplane/internal/service/casredirect.go:91`
- **Attacker:** Holder of a **project-scoped** API token (scoped to project X in
  org O) — a deliberately-restricted credential (e.g. one project's CI pipeline).
  Default token policies include `PolicyArtifactDownload`
  (`app/controlplane/pkg/biz/apitoken.go:117`).
- **Input:** The `digest` field of `GetDownloadURLRequest` — any valid
  `sha256:…` of an artifact in a **different** project Y of the same org O.

### Path
1. gRPC `CASRedirectService/GetDownloadURL`; authz middleware requires only
   `PolicyArtifactDownload` (`pkg/authz/authz.go:370`), which the token holds → passes.
2. Token branch calls
   `FindCASMappingForDownloadByOrg(ctx, req.Digest, []uuid.UUID{orgID}, nil)` —
   **`nil` project filter** (`casredirect.go:91`).
3. `CASMappingUseCase.FindCASMappingForDownloadByOrg` →
   `CASMappingRepo.FindByDigestInOrgs` (`pkg/data/casmapping.go:97`): with `nil`
   projectIDs, `projectIDs[o]` returns `ok=false` (line 110) → `else` branch
   (line 116) → predicate is `casmapping.OrganizationID(o)` **only**, no project scope.
4. Returns project Y's mapping → `GenerateTemporaryCredentials` mints a CAS
   downloader JWT for Y's backend + the requested digest (`casredirect.go:129-137`).

### Why the guard is absent here
The sibling `CASCredentialsService.Get` builds the filter from the token scope —
`projectIDs[orgID] = []uuid.UUID{*currentAPIToken.ProjectID}`
(`internal/service/cascredential.go:119-123`) — and passes it down.
`GetDownloadURL` is the same download-authorization operation but was never
updated to pass the token's `ProjectID`. The authz middleware is resource:action
only and never constrains which project a token may reach; project scoping is
enforced *solely* at this data-query filter, which is skipped here.

### Impact
Cross-project artifact-content disclosure within an org. A token confined to
project X obtains a working signed download URL for project Y's artifacts,
defeating the project-RBAC boundary established by commits 6f89362d6 /
96bbf574e / 16e184967.

### PoC
With a project-X token call
`/controlplane.v1.CASRedirectService/GetDownloadURL{digest: "sha256:<Y-artifact>"}`.
Observe `200` with `result.url` containing a valid `?t=<downloader-JWT>`; fetching
it returns project Y's bytes. The guarded `CASCredentialsService/Get{ROLE_DOWNLOADER}`
for the same digest returns `404`.

### Disconfirmation attempted
- No middleware project scoping for tokens (`middleware.go` is resource:action, no `ProjectID`).
- No project check inside `GetDownloadURL`.
- `GetDownloadURL` has no org-default fallback, so the single gap is the `nil` filter.
- The user/browser branch (`FindCASMappingForDownloadByUser`) correctly applies RBAC.

### Suggested fix
Mirror `cascredential.go`:
```go
projectIDs := make(map[uuid.UUID][]uuid.UUID)
if currentAPIToken.ProjectID != nil {
    projectIDs[orgID] = []uuid.UUID{*currentAPIToken.ProjectID}
}
mapping, err = s.casMappingUC.FindCASMappingForDownloadByOrg(ctx, req.Digest, []uuid.UUID{orgID}, projectIDs)
```

### Relates-to fingerprint
Lead 20/23 (6f89362d6, 16e184967) — unguarded sibling.

---

## Finding 2 — Unbounded `APITokenService/List` query (DoS)

- **Class / CWE / Severity:** Resource exhaustion / CWE-770 / **Medium**
- **Sink:** `app/controlplane/pkg/data/apitoken.go:159` (`query.Order(...).All(ctx)`)
- **Attacker:** Any low-privilege authenticated user. `RoleOrgContributor` /
  `RoleOrgMember` hold **both** `PolicyAPITokenCreate` and `PolicyAPITokenList`
  (`pkg/authz/authz.go:292-293`); `RoleProjectAdmin` holds create (`:339`).
- **Input:** `APITokenServiceListRequest` — has **no pagination field at all**
  (`api/controlplane/v1/api_token.proto`), so neither client nor server can bound it.

### Path
`APITokenService/List` (`internal/service/apitoken.go:93`) → `APITokenUseCase.List`
(no pagination arg) → `APITokenRepo.List` (`pkg/data/apitoken.go:159`) → `.All(ctx)`
with filters but **no `Limit`/`Offset`**. No per-org token-count cap in `Create`.

### Why the guard is absent here
All other attacker-growable list endpoints (workflow, group, project, workflowrun,
referrer) flow through a proto pagination request `buf.validate`-capped at ≤100
(`api/controlplane/v1/pagination.proto`) and apply `Limit`. This request type lacks
the pagination field entirely — the class the referrer fix 45fa952368 closed, but
worse: it cannot page even if the client wanted to.

### Impact
A low-priv member creates N tokens (each a row + generated JWT), then repeatedly
calls `List`, forcing an unbounded DB read and oversized gRPC response — bounded
only by tokens created.

### Disconfirmation attempted
Confirmed no pagination field on the request, no `Limit` in the data query, both
create+list held by low-priv roles, no token-count cap. Secondary (lower):
`OrgInvitationService/ListSent` (`pkg/data/orginvitation.go:144`) is also
unpaginated, but its collection only grows via admin-gated invites, so a low-priv
attacker can read-but-not-inflate it.

### Suggested fix
Add a `CursorPaginationRequest`/`OffsetPaginationRequest` field to
`APITokenServiceListRequest` (proto-capped at 100) and apply `Limit`/`Offset` in
`pkg/data/apitoken.go:159`, mirroring the workflow/group list pattern.

### Relates-to fingerprint
Lead 11 (45fa952368) — unguarded variant.

---

## Finding 3 — Org-viewer can hold group-maintainer, gaining group write powers

- **Class / CWE / Severity:** Missing authorization / privilege-boundary / CWE-269 / **Medium**
- **Sink:** `app/controlplane/pkg/biz/group.go:630`
  (`AddMemberToGroup(..., opts.Maintainer)`) and `:840` (`UpdateMemberMaintainerStatus`).
- **Attacker:** An existing **group maintainer** of group G — who need only be an
  org member/contributor, **not** an org admin — or an org admin/owner. The
  elevated beneficiary is an org **Viewer** (org-level read-only).
- **Input:** `GroupService/AddMember{group:G, userEmail:<a viewer>, isMaintainer:true}`
  or `UpdateMemberMaintainerStatus{IsMaintainer:true}`.

### Path
1. `GroupService/AddMember` has an **empty `{}` middleware policy**
   (`pkg/authz/authz.go:439-442`), so the org-role authz middleware admits everyone.
2. The service check `userHasPermissionOnGroupMembershipsWithPolicy`
   (`internal/service/group.go:620-631`) grants purely on the requester's **group
   resource-role** (`RoleGroupMaintainer`), with no org-role gate.
3. Reaches biz `addExistingUserToGroup` (`group.go:614`) → sink `:630`, which
   **never inspects the target user's org role**. The viewer is written as a group maintainer.

### Why the guard is absent here
Commit 536bc1aed added a check rejecting maintainer assignment when the target
holds org Viewer. At HEAD that guard exists **nowhere** — the only `RoleViewer`
comparisons in the group flow are the *requester's* group-role checks
(`group.go:552, 781`) and a permissive "viewers can list" test. No target-org-role
check survives in the biz or data layer.

### Impact
An org Viewer (supposed read-only) who holds `RoleGroupMaintainer` can then call
`GroupService/AddMember`, `RemoveMember`, and `UpdateMemberMaintainerStatus` on G
(empty middleware policy + maintainer resource-role passes the service check) —
write operations the org-viewer role must never perform, including minting further
maintainers and adding/removing members of a group that may gate project access.
A non-admin group maintainer can perform the elevating grant, so it is not
confined to fully-trusted operators.

### Disconfirmation attempted
The group-**derived project-admin** angle (Lead 16/17 part 2) is *not* additionally
exploitable via `ProjectService`: those endpoints require `PolicyProjectAddMemberships`,
which a Viewer's org role lacks, so the middleware blocks a viewer there. The live
gap is specifically the **group** endpoints, which carry empty middleware policies
and delegate entirely to the group resource-role. Confirmed no guard in biz
`addExistingUserToGroup`/`UpdateMemberMaintainerStatus`, in `data/group.go`, or the
service layer.

### Suggested fix
In `addExistingUserToGroup` and `UpdateMemberMaintainerStatus`, reject
`maintainer=true` when the target user's org membership role is `RoleViewer`
(re-introducing the 536bc1aed invariant).

### Relates-to fingerprint
Lead 18 (536bc1aed), related to Leads 16/17.

---

## Cross-tenant isolation review (org A → org B)

Reviewed for cross-**organization** exfiltration (distinct from the intra-org
cross-project issue in Finding 1). **Result: no cross-org exfiltration found.**
Every read/describe/download path that accepts an attacker-controlled ID or digest
is bounded to the caller's authenticated org — by an org-scoped query, a post-fetch
`OrgID` comparison, or a membership-derived org list.

### Digest-based lookups (highest-risk exfil vector) — all org-bounded
- **CAS artifact download** (`CASCredentialsService.Get`,
  `CASRedirectService.GetDownloadURL`, `WorkflowRunService.resolvePolicyEvaluations`):
  the `orgs` slice is built exclusively from the caller — `[]uuid.UUID{orgID}` with
  `orgID = currentOrg` (`cascredential.go:123`, `casredirect.go:91`,
  `workflowrun.go:109`), or from the user's own memberships via
  `GetOrgsAndRBACInfoForUser` (`casmapping.go:102`). `FindByDigestInOrgs` ANDs each
  digest match with `casmapping.OrganizationID(o)` (`data/casmapping.go:108-120`).
  (This is the same lookup as Finding 1; the org bound is intact — only the *project*
  filter within the org is missing.)
- **WorkflowRun by digest** (`GetByDigestInOrg`): repo `FindByAttestationDigest` is
  unscoped, but the biz layer rejects with
  `if wfrun.Workflow.OrgID != orgUUID { return NotFound }` (`biz/workflowrun.go:649`).
- **Referrer `DiscoverPrivate`**: user path uses memberships only
  (`biz/referrer.go:175`); token path passes `[]uuid.UUID{orgUUID}` from `currentOrg`
  (`service/referrer.go:87`); data layer bounds every query with
  `workflow.HasOrganizationWith(organization.IDIn(orgIDs...))` (`data/referrer.go:167,335`).

### ID-based lookups — all org-scoped or post-checked
`WorkflowRun View by ID` (`GetByIDInOrg` → `orgScopedQuery`), `Workflow View`
(`FindByNameInOrg`), `Contract Describe` (`FindByNameInOrg` + `Describe(currentOrg.ID)`),
`Group Get` (`FindByOrgAndID`), `Project ListMembers` (`userHasPermissionOnProject`
+ `ListMembers(orgUUID)`), `API token Get` (`FindByIDInOrg(currentOrg.ID)`),
`CAS backend Update/Delete/Revalidate` (`FindByNameInOrg(currentOrg.ID)`),
`Org invitation Revoke` (unscoped `FindByID` + `if m.Org.ID != orgID { NotFound }`).

### Defense-in-depth note (not a live finding)
`OrgInvitationUseCase.AcceptInvitation` and `OrgInvitationUseCase.FindByID`
(`biz/orginvitation.go:339,351`) are org-unscoped and would invert the tenant check,
but are **not wired to any RPC** (no service caller — only test references). They are
inert relative to the tenant boundary today; maintainers should keep them unexposed
or add org-scoping before wiring them to any endpoint. Similarly, several other
unscoped `FindByID` helpers (`CASBackendUseCase.Delete`/`PerformValidation`,
`RobotAccount`/`APIToken` auth-middleware lookups, `WorkflowContractUseCase.FindVersionByID`)
are reached only with IDs already resolved from an org-scoped lookup or from the
caller's own signed credential, so they do not accept a cross-org reference.
