# agent-did-interop

Interoperability fixtures between [Agent-DID](https://github.com/edisonduran/agent-did) and other agent-identity and authority specifications. Each fixture runs the published implementations of both sides against the same inputs and records each side's result separately.

This repository is not part of either project's release. Neither core depends on it, and it depends only on published packages.

## Pin sets

Each directory is one **pin set**: one fixed version of each specification and implementation. The directory name lists the pins.

| Directory | Specification | Implementations | Status |
|---|---|---|---|
| [`aps-04_aps-8.0.1_agent-did-rc.4/`](aps-04_aps-8.0.1_agent-did-rc.4/) | [draft-pidlisnyi-aps-04](https://www.ietf.org/archive/id/draft-pidlisnyi-aps-04.html) §4.1–4.3 (`AuthorityDelegationV1`), §3.4 | `agent-passport-system` 8.0.1, `@agentdid/sdk` 1.0.0-rc.4 | Draft: case 8 is proposed |

## Rules

- **Results are attributed separately.** Each case has one column per project, and each project's maintainer owns their column. A change to a column needs that maintainer's review.
- **Pins are exact.** Implementations are pinned to exact versions in each directory's `package.json` and lockfile. Fixture inputs (DID logs, signed records) are committed, so a run does not regenerate them.
- **Each case states what it exercises.** A check that a pinned implementation does not perform is reported as not exercised, never as passed.
- **A published directory does not change.** A correction, or a new version of any pin, goes into a new directory. Draft directories may still change until their cases are agreed.
- **A run is not an endorsement.** A passing case states what the two implementations did with these inputs. It is not a certification or a conformance claim about either project.

## Running a pin set

```bash
cd aps-04_aps-8.0.1_agent-did-rc.4
npm ci
npm test        # runs every case, writes results.json, exits 1 on any difference from cases.json
```

Requires Node 22.12 or later.

## License

Apache-2.0. See [LICENSE](LICENSE).
