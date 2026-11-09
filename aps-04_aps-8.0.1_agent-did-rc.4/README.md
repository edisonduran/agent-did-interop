# APS `AuthorityDelegationV1` × Agent-DID `did:webvh` issuers

**Status: draft.** Cases 1–7 are agreed in [aeoess/agent-governance-vocabulary#177](https://github.com/aeoess/agent-governance-vocabulary/issues/177). Case 8 is proposed and not yet confirmed.

## Pins

| | Pin |
|---|---|
| APS specification | [draft-pidlisnyi-aps-04](https://www.ietf.org/archive/id/draft-pidlisnyi-aps-04.html): §4.1–4.3 (`AuthorityDelegationV1`), §3.4 (key-validity boundary), §2.5 (resolution outcomes) |
| APS implementation | `agent-passport-system` 8.0.1 (TypeScript) |
| Agent-DID implementation | `@agentdid/sdk` 1.0.0-rc.4 (TypeScript) |
| Agent-DID rule | The key named in `verification_method` is listed under `capabilityDelegation` in the issuer's DID document at `issued_at` (RFC-001 §6.2.1) |

## Question

An APS root delegation is issued by an Agent-DID `did:webvh` DID. The two columns answer different questions:

- **APS:** does the delegation chain verify? `verifyAuthorityDelegationChain` asks a caller-supplied resolver for the issuer's key at `issued_at`. It does not inspect the DID document or its verification relationships.
- **Agent-DID:** did the issuer's DID authorize that key to issue delegations at `issued_at`?

A valid APS chain alone doesn't show that the DID authorized the key for delegation, so the two results are reported apart.

## Inputs

| File | What |
|---|---|
| `logs/relationships.did.jsonl` | Issuer with three keys: `#delegation` under `capabilityDelegation`, `#assertion` under `assertionMethod`, `#key-agreement` under `keyAgreement`. One entry, created 2026-01-01. |
| `logs/rotated.did.jsonl` | Issuer whose `#key-1` (under `capabilityDelegation`) is replaced by `#key-2` on 2026-03-01. |
| `logs/deactivated.did.jsonl` | Issuer created 2026-01-01 with `#key-1` under `capabilityDelegation`, then deactivated. The deactivation entry carries the time the fixture was generated, because rc.4 stamps it with the current time. |
| `delegations/case-N.json` | One `AuthorityDelegationV1` root record per case, issued with `issueAuthorityDelegation`. |
| `cases.json` | Each case's inputs and expected results. |

`generate.mjs` produced these files once. It generates fresh keys and writes no private key. `run.mjs` only reads the committed files.

## Resolver given to APS

`VerificationKeyResolver` is synchronous in 8.0.1, so each answer is computed before the APS call, from the issuer's log verified with `resolveDidWebvhLog`. The resolver does not apply the Agent-DID relationship rule:

- `{ outcome: 'not_found' }` if the key never appears in the issuer's log.
- `{ outcome: 'ambiguous' }` if the log shows the key retired, or the DID deactivated, at any time. The claimed `issued_at` alone cannot place the signature on either side of that boundary (§3.4).
- Otherwise, the Ed25519 key from the DID state at `issued_at`, decoded from `publicKeyMultibase` to 64 hex characters.

Other options: `now` is `2026-11-01T00:00:00.000Z`, `trustRoot` accepts the case's issuer DID, and `resolveRevocation` returns `active`.

## Agent-DID column

| Step | Source |
|---|---|
| Verify the issuer's log and take the DID state at `issued_at` | SDK: `resolveDidWebvhLog(log, { did, versionTime: issued_at })`. rc.4 doesn't export it from the package root, so it is imported from `@agentdid/sdk/dist/webvh/adapter.js` |
| Check that the key is listed under `capabilityDelegation` | SDK: `assertKeyPurpose(keyId, document, 'capabilityDelegation')` |
| Find a later log entry that retires the key or deactivates the DID | **Fixture logic**, over the verified log. rc.4 has no indeterminate outcome, so this step is not an SDK check. |

The Agent-DID column does not check the APS signature. That is APS's check.

## Cases

| # | Case | APS chain | Agent-DID |
|---|---|---|---|
| 1 | Key only under `capabilityDelegation` | valid | authorized |
| 2 | Key only under `assertionMethod` | valid | rejected: wrong relationship |
| 3 | Key only under `keyAgreement` | valid | rejected: wrong relationship |
| 4 | Delegation modified after signing | invalid, `SIGNATURE_INVALID` | not exercised |
| 5 | Key retired before `issued_at` | indeterminate, `KEY_AMBIGUOUS` | rejected: key not in the DID state at `issued_at` |
| 6 | Key retired after `issued_at` | indeterminate, `KEY_AMBIGUOUS` | indeterminate: signing time not established |
| 7 | DID deactivated after `issued_at` | indeterminate, `KEY_AMBIGUOUS` | indeterminate: signing time not established |
| 8 *(proposed)* | Key never listed in the issuer's DID | indeterminate, `KEY_NOT_FOUND` | rejected: key not in the DID state at `issued_at` |

These are the results of `npm test` with the pins above, and they match the expected results in `cases.json`. `results.json` holds the full output.

Notes on the cases:

- **Case 4.** The record's scope is changed after signing and `delegation_id` is recomputed, so the signature is the only thing that no longer matches.
- **Case 5.** The two columns differ on purpose:
  - Agent-DID checks the key at the claimed `issued_at`, and the key isn't in the DID at that time.
  - APS treats the claimed time as unproven, so a retirement anywhere in the log makes the key ambiguous. The APS author corrected this case from `KEY_NOT_FOUND` in [#177](https://github.com/aeoess/agent-governance-vocabulary/issues/177#issuecomment-6747421782).
- **Case 7.** `KEY_AMBIGUOUS` is the APS author's reading of §3.4's general rule. The draft does not address DID deactivation explicitly.
- **Cases 5–7, control.** For each indeterminate APS result, `run.mjs` also verifies the record with the key taken from the log, and the result is valid. So the indeterminate outcome comes from the resolver's answer, not from a broken signature.

## Not exercised

- Delegation chains longer than one record. Every case is a root that the trust policy accepts.
- Revocation. `resolveRevocation` always returns `active`.
- Any APS implementation other than the TypeScript 8.0.1 package.
- The Agent-DID Python SDK.
- Fetching logs over HTTPS. Logs are read from files.

## Running

```bash
npm ci
npm test
```
