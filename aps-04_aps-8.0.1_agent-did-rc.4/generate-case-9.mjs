// Generates the inputs of case 9 only: logs/added.did.jsonl and delegations/case-9.json.
// Run once; the outputs are committed and run.mjs only reads them.
//
// This is a separate script so that cases 1-8 keep the inputs that were already
// reviewed: generate.mjs creates fresh keys on every run, and rc.4 stamps the
// deactivation entry of case 7 with the current time. Keys are generated fresh and
// discarded: no private key is written.
//
// Issuer "added": created with #key-1, then #key-2 is added and #key-1 kept, so the
// log shows no retirement and no deactivation. The case-9 record is signed with
// #key-2 and claims an issued_at before #key-2 was added.

import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import sdk from '@agentdid/sdk';
import adapter from '@agentdid/sdk/dist/webvh/adapter.js';
import multibase from '@agentdid/sdk/dist/crypto/multibase.js';
import { issueAuthorityDelegation } from 'agent-passport-system';

const { LocalKeySigner } = sdk;
const { createDidWebvhLog, updateDidWebvhLog } = adapter;
const { encodePublicKeyMultibase } = multibase;

const HERE = dirname(fileURLToPath(import.meta.url));
// Same constants as generate.mjs.
const DOMAIN = 'issuers.interop.example';
const CONTEXT = ['https://www.w3.org/ns/did/v1'];
const SUBJECT = 'did:web:subject.interop.example';
const T_CREATED = '2026-01-01T00:00:00Z';
const T_ADDED = '2026-03-01T00:00:00Z';
const ISSUED_BEFORE_ADDED = '2026-02-01T00:00:00.000Z';
const NOT_AFTER = '2027-12-31T00:00:00.000Z';

function keyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  return {
    privateKeyHex: Buffer.from(privateKey.subarray(-32)).toString('hex'),
    publicKeyBytes: new Uint8Array(publicKey.subarray(-32)),
  };
}

const method = (fragment, key) => ({
  id: `{DID}#${fragment}`,
  type: 'Ed25519VerificationKey2020',
  controller: '{DID}',
  publicKeyMultibase: encodePublicKeyMultibase(key.publicKeyBytes),
});

const document = (methods, capabilityDelegation) => ({
  '@context': CONTEXT,
  id: '{DID}',
  controller: '{DID}',
  verificationMethod: methods,
  capabilityDelegation: capabilityDelegation.map((fragment) => `{DID}#${fragment}`),
});

const fill = (doc, did) => JSON.parse(JSON.stringify(doc).replaceAll('{DID}', did));

const controller = new LocalKeySigner(keyPair().privateKeyHex);
const key1 = keyPair();
const key2 = keyPair();
const created = await createDidWebvhLog({
  domain: DOMAIN,
  pathSegments: ['added'],
  signer: controller,
  created: T_CREATED,
  document: document([method('key-1', key1)], ['key-1']),
});
const did = created.did;
const added = await updateDidWebvhLog({
  log: created.log,
  signer: controller,
  updated: T_ADDED,
  document: fill(document([method('key-1', key1), method('key-2', key2)], ['key-1', 'key-2']), did),
});

const record = issueAuthorityDelegation({
  record_type: 'aps:authority-delegation:v1',
  version: '1.0',
  parent_delegation_id: null,
  issuer: did,
  subject: SUBJECT,
  verification_method: `${did}#key-2`,
  issued_at: ISSUED_BEFORE_ADDED,
  nonce: randomBytes(16).toString('hex'),
  authority: {
    scope: { profile: 'aps-hierarchical-v1', grants: ['interop:read'] },
    spend: { mode: 'unbounded' },
    depth: { remaining: 0 },
    time: { not_before: ISSUED_BEFORE_ADDED, not_after: NOT_AFTER },
    reputation: { profile: 'aps-score-0-100-v1', ceiling: 100 },
    values: { profile: 'aps-values-identifiers-v1', required: [] },
    reversibility: { profile: 'aps-tci-v1', ceiling: 'tentative' },
  },
}, key2.privateKeyHex);

mkdirSync(join(HERE, 'logs'), { recursive: true });
mkdirSync(join(HERE, 'delegations'), { recursive: true });
writeFileSync(join(HERE, 'logs', 'added.did.jsonl'), added.log);
writeFileSync(join(HERE, 'delegations', 'case-9.json'), `${JSON.stringify(record, null, 2)}\n`);
console.log({ added: did });
