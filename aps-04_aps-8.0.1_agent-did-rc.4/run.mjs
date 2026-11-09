// Runs every case of this pin set and writes results.json.
//
// Two columns, attributed separately:
// - APS: agent-passport-system 8.0.1, verifyAuthorityDelegationChain on a one-record
//   chain. The key resolver below gives it the issuer's key from the did:webvh log; it
//   does not apply Agent-DID's relationship rule.
// - Agent-DID: @agentdid/sdk 1.0.0-rc.4. Log verification and the state at issued_at
//   come from resolveDidWebvhLog; the relationship check is assertKeyPurpose. rc.4 has
//   no indeterminate outcome, so the "later boundary" step is computed here from the
//   verified log and reported as fixture logic, not as an SDK check.
//
// Exit code 1 if any result differs from cases.json.

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import sdk from '@agentdid/sdk';
import adapter from '@agentdid/sdk/dist/webvh/adapter.js';
import multibase from '@agentdid/sdk/dist/crypto/multibase.js';
import { verifyAuthorityDelegationChain } from 'agent-passport-system';

const { assertKeyPurpose } = sdk;
const { resolveDidWebvhLog } = adapter;
const { decodePublicKeyMultibase } = multibase;

const HERE = dirname(fileURLToPath(import.meta.url));
const read = (path) => readFileSync(join(HERE, path), 'utf8');
const spec = JSON.parse(read('cases.json'));

// --- Verified log history, one state per entry -----------------------------------

async function loadHistory(path) {
  const text = read(path);
  const latest = await resolveDidWebvhLog(text); // verifies the whole log
  const entries = [];
  for (let n = 1; n <= latest.metadata.versionNumber; n += 1) {
    const r = await resolveDidWebvhLog(text, { did: latest.did, versionNumber: n });
    entries.push({ versionTime: r.metadata.versionTime, deactivated: r.metadata.deactivated, state: r.state });
  }
  return { did: latest.did, text, entries };
}

const methodOf = (state, id) => (state.verificationMethod ?? []).find((m) => m.id === id);
const millis = (t) => Date.parse(t);

/** Entries in effect at `at`, and the first later entry that retires `id` or deactivates the DID. */
function timeline(history, id, at) {
  const effective = history.entries.filter((e) => millis(e.versionTime) <= millis(at)).at(-1);
  const later = history.entries.filter((e) => millis(e.versionTime) > millis(at));
  const boundary = later.find((e) => e.deactivated || !methodOf(e.state, id));
  return { effective, boundary };
}

// --- APS column: caller-supplied resolver (§2.5, §3.4) ---------------------------
//
// Returns the key as 64 hex characters, or:
// - { outcome: 'not_found' }  if the key never appears in the issuer's log, or is not
//   in the DID state at issued_at for a reason other than a retirement;
// - { outcome: 'ambiguous' }  if the log shows the key retired or the DID deactivated,
//   at any time: the claimed issued_at alone cannot place the signature on either
//   side of that boundary (#177, comment 6747421782).
//
// That rule holds because no case carries independent evidence of the signing time.
// With acceptable evidence (a timestamp, a transparency-log entry), a verifier could
// place the signature and decide whether the key was authorized (#177, comment
// 6752140683). This pin set does not exercise that.

function apsResolution(history, id, issuedAt) {
  const appearances = history.entries.map((e) => Boolean(methodOf(e.state, id)));
  if (!appearances.includes(true)) return { outcome: 'not_found' };
  const first = appearances.indexOf(true);
  const retired = appearances.slice(first).includes(false);
  const deactivated = history.entries.some((e) => e.deactivated);
  if (retired || deactivated) return { outcome: 'ambiguous' };
  const { effective } = timeline(history, id, issuedAt);
  const method = effective && methodOf(effective.state, id);
  if (!method) return { outcome: 'not_found' };
  return Buffer.from(decodePublicKeyMultibase(method.publicKeyMultibase)).toString('hex');
}

function runAps(history, delegation) {
  // VerificationKeyResolver is synchronous in 8.0.1: answers are computed up front.
  const answer = apsResolution(history, delegation.verification_method, delegation.issued_at);
  const result = verifyAuthorityDelegationChain([delegation], {
    now: spec.verification_options.now,
    resolveVerificationKey: (issuer, verificationMethod, issuedAt) =>
      issuer === history.did
        && verificationMethod === delegation.verification_method
        && issuedAt === delegation.issued_at
        ? answer
        : { outcome: 'not_found' },
    trustRoot: (root) => root.issuer === history.did,
    resolveRevocation: () => 'active',
  });
  const out = {
    state: result.state,
    codes: result.failures.map((f) => f.code),
    resolver_answer: typeof answer === 'string' ? 'key' : answer.outcome,
  };
  // Control for an indeterminate key answer: give APS the key from any log entry that
  // lists it. A valid result shows the signature itself is good, so the indeterminate
  // outcome comes from the resolver's answer and not from a broken record.
  if (typeof answer !== 'string') {
    const listed = history.entries.map((e) => methodOf(e.state, delegation.verification_method)).find(Boolean);
    if (listed) {
      const key = Buffer.from(decodePublicKeyMultibase(listed.publicKeyMultibase)).toString('hex');
      const control = verifyAuthorityDelegationChain([delegation], {
        now: spec.verification_options.now,
        resolveVerificationKey: () => key,
        trustRoot: (root) => root.issuer === history.did,
        resolveRevocation: () => 'active',
      });
      out.control_with_listed_key = control.state;
    } else {
      out.control_with_listed_key = 'no_listed_key';
    }
  }
  return out;
}

// --- Agent-DID column ------------------------------------------------------------

async function runAgentDid(history, delegation) {
  const id = delegation.verification_method;
  const checks = {};
  const atIssued = await resolveDidWebvhLog(history.text, { did: history.did, versionTime: delegation.issued_at });
  checks.log_verified = 'sdk: resolveDidWebvhLog';
  if (!methodOf(atIssued.state, id)) {
    return { result: 'rejected', reason: 'key_not_in_did_state', checks };
  }
  checks.state_at_issued_at = 'sdk: resolveDidWebvhLog({ versionTime: issued_at })';
  try {
    assertKeyPurpose(id, atIssued.document, 'capabilityDelegation');
  } catch (error) {
    if (error?.reason !== 'key_purpose_violation') throw error;
    return { result: 'rejected', reason: 'wrong_relationship', checks };
  }
  checks.relationship = 'sdk: assertKeyPurpose(capabilityDelegation)';
  const { boundary } = timeline(history, id, delegation.issued_at);
  checks.later_boundary = 'fixture: later log entry retires the key or deactivates the DID';
  if (boundary) {
    return { result: 'indeterminate', reason: 'signing_time_not_established', checks };
  }
  return { result: 'authorized', checks };
}

// --- Run -------------------------------------------------------------------------

const histories = new Map();
const results = [];
let mismatches = 0;

for (const c of spec.cases) {
  if (!histories.has(c.issuer_log)) histories.set(c.issuer_log, await loadHistory(c.issuer_log));
  const history = histories.get(c.issuer_log);
  const delegation = JSON.parse(read(c.delegation));

  const aps = runAps(history, delegation);
  const agentDid = c.agent_did_exercised === false
    ? { result: 'not_exercised' }
    : await runAgentDid(history, delegation);

  const apsMatch = aps.state === c.expected.aps.state
    && (c.expected.aps.code === undefined || aps.codes.includes(c.expected.aps.code));
  const agentDidMatch = agentDid.result === c.expected.agent_did.result
    && (c.expected.agent_did.reason === undefined || agentDid.reason === c.expected.agent_did.reason);
  if (!apsMatch || !agentDidMatch) mismatches += 1;

  results.push({
    id: c.id,
    title: c.title,
    status: c.status,
    aps: { ...aps, expected: c.expected.aps, matches_expected: apsMatch },
    agent_did: { ...agentDid, expected: c.expected.agent_did, matches_expected: agentDidMatch },
  });
}

const out = { pins: spec.pins, verification_options: spec.verification_options, results };
writeFileSync(join(HERE, 'results.json'), `${JSON.stringify(out, null, 2)}\n`);

for (const r of results) {
  const aps = `${r.aps.state}${r.aps.codes.length ? ` ${r.aps.codes.join(',')}` : ''}`;
  const ad = `${r.agent_did.result}${r.agent_did.reason ? ` ${r.agent_did.reason}` : ''}`;
  const mark = r.aps.matches_expected && r.agent_did.matches_expected ? 'ok      ' : 'MISMATCH';
  const control = r.aps.control_with_listed_key ? ` (control: ${r.aps.control_with_listed_key})` : '';
  console.log(`${mark} ${r.id} [${r.status}] APS: ${aps}${control} | Agent-DID: ${ad}`);
}
console.log(`node ${process.version}`);
if (mismatches > 0) {
  console.error(`${mismatches} case(s) differ from cases.json`);
  process.exit(1);
}
