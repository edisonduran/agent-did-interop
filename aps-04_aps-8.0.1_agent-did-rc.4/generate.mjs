// Generates the inputs of this pin set: the issuers' did:webvh logs and the
// AuthorityDelegationV1 records. Run once; the outputs are committed and run.mjs
// only reads them. Keys are generated fresh and discarded: no private key is written.
//
// Agent-DID side: @agentdid/sdk 1.0.0-rc.4. Its did:webvh log functions are not
// exported from the package root in rc.4, so they are imported from the adapter module.
// APS side: agent-passport-system 8.0.1, issueAuthorityDelegation.

import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import sdk from '@agentdid/sdk';
import adapter from '@agentdid/sdk/dist/webvh/adapter.js';
import multibase from '@agentdid/sdk/dist/crypto/multibase.js';
import {
  computeAuthorityDelegationId,
  issueAuthorityDelegation,
} from 'agent-passport-system';

const { LocalKeySigner } = sdk;
const { createDidWebvhLog, updateDidWebvhLog, deactivateDidWebvhLog } = adapter;
const { encodePublicKeyMultibase } = multibase;

const HERE = dirname(fileURLToPath(import.meta.url));
const DOMAIN = 'issuers.interop.example';
const CONTEXT = ['https://www.w3.org/ns/did/v1'];
const SUBJECT = 'did:web:subject.interop.example';

// Log timeline (did:webvh versionTime, second precision).
const T_CREATED = '2026-01-01T00:00:00Z';
const T_ROTATED = '2026-03-01T00:00:00Z';
// Claimed signing times (APS canonical UTC milliseconds).
const ISSUED_BEFORE_BOUNDARY = '2026-02-01T00:00:00.000Z';
const ISSUED_AFTER_ROTATION = '2026-04-01T00:00:00.000Z';
const NOT_AFTER = '2027-12-31T00:00:00.000Z';

function keyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  const pub = Buffer.from(publicKey.subarray(-32));
  return {
    privateKeyHex: Buffer.from(privateKey.subarray(-32)).toString('hex'),
    publicKeyBytes: new Uint8Array(pub),
    publicKeyHex: pub.toString('hex'),
  };
}

function method(fragment, key) {
  return {
    id: `{DID}#${fragment}`,
    type: 'Ed25519VerificationKey2020',
    controller: '{DID}',
    publicKeyMultibase: encodePublicKeyMultibase(key.publicKeyBytes),
  };
}

function document(methods, relationships) {
  const doc = { '@context': CONTEXT, id: '{DID}', controller: '{DID}', verificationMethod: methods };
  for (const [relationship, fragments] of Object.entries(relationships)) {
    doc[relationship] = fragments.map((fragment) => `{DID}#${fragment}`);
  }
  return doc;
}

function fill(doc, did) {
  return JSON.parse(JSON.stringify(doc).replaceAll('{DID}', did));
}

function body(issuer, fragment, issuedAt) {
  return {
    record_type: 'aps:authority-delegation:v1',
    version: '1.0',
    parent_delegation_id: null,
    issuer,
    subject: SUBJECT,
    verification_method: `${issuer}#${fragment}`,
    issued_at: issuedAt,
    nonce: randomBytes(16).toString('hex'),
    authority: {
      scope: { profile: 'aps-hierarchical-v1', grants: ['interop:read'] },
      spend: { mode: 'unbounded' },
      depth: { remaining: 0 },
      time: { not_before: issuedAt, not_after: NOT_AFTER },
      reputation: { profile: 'aps-score-0-100-v1', ceiling: 100 },
      values: { profile: 'aps-values-identifiers-v1', required: [] },
      reversibility: { profile: 'aps-tci-v1', ceiling: 'tentative' },
    },
  };
}

const logs = {};
const delegations = {};

// Issuer "relationships": one key per relationship, never rotated (cases 1-4, 8).
{
  const controller = new LocalKeySigner(keyPair().privateKeyHex);
  const cap = keyPair();
  const assert = keyPair();
  const ka = keyPair();
  const created = await createDidWebvhLog({
    domain: DOMAIN,
    pathSegments: ['relationships'],
    signer: controller,
    created: T_CREATED,
    document: document(
      [method('delegation', cap), method('assertion', assert), method('key-agreement', ka)],
      {
        capabilityDelegation: ['delegation'],
        assertionMethod: ['assertion'],
        keyAgreement: ['key-agreement'],
      },
    ),
  });
  logs.relationships = created;
  const did = created.did;
  delegations['case-1'] = issueAuthorityDelegation(body(did, 'delegation', ISSUED_BEFORE_BOUNDARY), cap.privateKeyHex);
  delegations['case-2'] = issueAuthorityDelegation(body(did, 'assertion', ISSUED_BEFORE_BOUNDARY), assert.privateKeyHex);
  delegations['case-3'] = issueAuthorityDelegation(body(did, 'key-agreement', ISSUED_BEFORE_BOUNDARY), ka.privateKeyHex);

  // Case 4: case 1's record with its scope changed after signing. delegation_id is
  // recomputed over the changed body, so the only thing that no longer matches is the
  // signature.
  const tampered = JSON.parse(JSON.stringify(delegations['case-1']));
  tampered.authority.scope.grants = ['interop:write'];
  const { delegation_id: _id, signature: _sig, ...tamperedBody } = tampered;
  tampered.delegation_id = computeAuthorityDelegationId(tamperedBody);
  delegations['case-4'] = tampered;

  // Case 8: a key the issuer's DID never listed. Signed with a fresh key.
  delegations['case-8'] = issueAuthorityDelegation(body(did, 'unlisted', ISSUED_BEFORE_BOUNDARY), keyPair().privateKeyHex);
}

// Issuer "rotated": #key-1 replaced by #key-2 at T_ROTATED (cases 5, 6).
{
  const controller = new LocalKeySigner(keyPair().privateKeyHex);
  const key1 = keyPair();
  const key2 = keyPair();
  const created = await createDidWebvhLog({
    domain: DOMAIN,
    pathSegments: ['rotated'],
    signer: controller,
    created: T_CREATED,
    document: document([method('key-1', key1)], { capabilityDelegation: ['key-1'] }),
  });
  const did = created.did;
  const rotated = await updateDidWebvhLog({
    log: created.log,
    signer: controller,
    updated: T_ROTATED,
    document: fill(document([method('key-2', key2)], { capabilityDelegation: ['key-2'] }), did),
  });
  logs.rotated = rotated;
  delegations['case-5'] = issueAuthorityDelegation(body(did, 'key-1', ISSUED_AFTER_ROTATION), key1.privateKeyHex);
  delegations['case-6'] = issueAuthorityDelegation(body(did, 'key-1', ISSUED_BEFORE_BOUNDARY), key1.privateKeyHex);
}

// Issuer "deactivated": DID deactivated after the claimed signing time (case 7).
// rc.4's deactivateDidWebvhLog stamps the entry with the current time.
{
  const controller = new LocalKeySigner(keyPair().privateKeyHex);
  const key1 = keyPair();
  const created = await createDidWebvhLog({
    domain: DOMAIN,
    pathSegments: ['deactivated'],
    signer: controller,
    created: T_CREATED,
    document: document([method('key-1', key1)], { capabilityDelegation: ['key-1'] }),
  });
  const deactivated = await deactivateDidWebvhLog({ log: created.log, signer: controller });
  logs.deactivated = deactivated;
  delegations['case-7'] = issueAuthorityDelegation(body(created.did, 'key-1', ISSUED_BEFORE_BOUNDARY), key1.privateKeyHex);
}

mkdirSync(join(HERE, 'logs'), { recursive: true });
mkdirSync(join(HERE, 'delegations'), { recursive: true });
for (const [name, result] of Object.entries(logs)) {
  writeFileSync(join(HERE, 'logs', `${name}.did.jsonl`), result.log);
}
for (const [name, record] of Object.entries(delegations)) {
  writeFileSync(join(HERE, 'delegations', `${name}.json`), `${JSON.stringify(record, null, 2)}\n`);
}
console.log(Object.fromEntries(Object.entries(logs).map(([name, r]) => [name, r.did])));
