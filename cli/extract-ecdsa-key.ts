#!/usr/bin/env npx tsx
/**
 * CLI tool to extract ECDSA public keys from UIC barcode ticket signatures.
 *
 * Given one or more tickets signed with the same Level 1 key, recovers the
 * public key using ECDSA signature recovery. A single signature yields two
 * candidate keys; using multiple tickets narrows it down to the real one.
 *
 * Usage:
 *   npx tsx cli/extract-ecdsa-key.ts <ticket1> <ticket2> [...]
 *   npx tsx cli/extract-ecdsa-key.ts ardeche ain drome
 *   npx tsx cli/extract-ecdsa-key.ts path/to/ticket1.hex path/to/ticket2.hex
 *
 * Each argument can be a built-in fixture name, a path to a .hex file,
 * or inline hex data.
 *
 * Built-in fixtures: sample, sncf, solea, cts, grand_est, ardeche, ain, drome
 */

import * as fs from 'fs';
import { p256, p384, p521 } from '@noble/curves/nist.js';
import { sha256, sha384, sha512 } from '@noble/hashes/sha2.js';
import { extractSignedData } from '../src/signed-data';
import { derToRaw } from '../src/signature-utils';
import { getSigningAlgorithm, getKeyAlgorithm, curveComponentLength } from '../src/oids';
import {
  SAMPLE_TICKET_HEX,
  SNCF_TER_TICKET_HEX,
  SOLEA_TICKET_HEX,
  CTS_TICKET_HEX,
  GRAND_EST_U1_FCB3_HEX,
  BUS_ARDECHE_TICKET_HEX,
  BUS_AIN_TICKET_HEX,
  DROME_BUS_TICKET_HEX,
} from '../src/fixtures';

// ---------------------------------------------------------------------------
// Named fixtures
// ---------------------------------------------------------------------------

const FIXTURES: Record<string, string> = {
  sample: SAMPLE_TICKET_HEX,
  sncf: SNCF_TER_TICKET_HEX,
  sncf_ter: SNCF_TER_TICKET_HEX,
  solea: SOLEA_TICKET_HEX,
  cts: CTS_TICKET_HEX,
  grand_est: GRAND_EST_U1_FCB3_HEX,
  ardeche: BUS_ARDECHE_TICKET_HEX,
  ain: BUS_AIN_TICKET_HEX,
  drome: DROME_BUS_TICKET_HEX,
};

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const CYAN = '\x1b[36m';
const DIM = '\x1b[2m';
const BOLD = '\x1b[1m';
const RESET = '\x1b[0m';

function ok(msg: string) { console.log(`  ${GREEN}✓${RESET} ${msg}`); }
function fail(msg: string) { console.log(`  ${RED}✗${RESET} ${msg}`); }
function warn(msg: string) { console.log(`  ${YELLOW}⚠${RESET} ${msg}`); }
function heading(msg: string) { console.log(`\n${BOLD}${CYAN}${msg}${RESET}`); }

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/[\s\n\r]/g, '');
  return new Uint8Array(clean.match(/.{1,2}/g)!.map(b => parseInt(b, 16)));
}

// ---------------------------------------------------------------------------
// Curve dispatch
// ---------------------------------------------------------------------------

interface CurveOps {
  name: string;
  componentLength: number;
  hash: (data: Uint8Array) => Uint8Array;
  signatureFromBytes: (raw: Uint8Array) => { addRecoveryBit(bit: number): { recoverPublicKey(msgHash: Uint8Array): { toBytes(): Uint8Array } } };
  verify: (sig: Uint8Array, msg: Uint8Array, pk: Uint8Array) => boolean;
}

function getCurveOps(curve: string): CurveOps {
  const VERIFY_OPTS = { lowS: false } as const;

  switch (curve) {
    case 'P-256':
      return {
        name: 'P-256',
        componentLength: 32,
        hash: sha256,
        signatureFromBytes: (raw) => p256.Signature.fromBytes(raw),
        verify: (sig, msg, pk) => p256.verify(sig, msg, pk, VERIFY_OPTS),
      };
    case 'P-384':
      return {
        name: 'P-384',
        componentLength: 48,
        hash: sha384,
        signatureFromBytes: (raw) => p384.Signature.fromBytes(raw),
        verify: (sig, msg, pk) => p384.verify(sig, msg, pk, VERIFY_OPTS),
      };
    case 'P-521':
      return {
        name: 'P-521',
        componentLength: 66,
        hash: sha512,
        signatureFromBytes: (raw) => p521.Signature.fromBytes(raw),
        verify: (sig, msg, pk) => p521.verify(sig, msg, pk, VERIFY_OPTS),
      };
    default:
      throw new Error(`Unsupported curve: ${curve}`);
  }
}

// ---------------------------------------------------------------------------
// Recovery logic
// ---------------------------------------------------------------------------

interface TicketInfo {
  label: string;
  provider: number;
  keyId: number;
  curve: string;
  sigAlg: string;
  level1DataBytes: Uint8Array;
  rawSig: Uint8Array;
  msgHash: Uint8Array;
}

function extractTicketInfo(label: string, hex: string): TicketInfo {
  const bytes = hexToBytes(hex);
  const extracted = extractSignedData(bytes);
  const { security } = extracted;

  if (!security.level1Signature) {
    throw new Error(`${label}: no Level 1 signature`);
  }

  const sigAlg = security.level1SigningAlg
    ? getSigningAlgorithm(security.level1SigningAlg)
    : undefined;

  if (!sigAlg || sigAlg.type !== 'ECDSA') {
    throw new Error(`${label}: Level 1 is not ECDSA (${sigAlg?.type ?? 'unknown'})`);
  }

  const keyAlg = security.level1KeyAlg
    ? getKeyAlgorithm(security.level1KeyAlg)
    : undefined;

  const curve = keyAlg?.curve;
  if (!curve) {
    throw new Error(`${label}: cannot determine curve from key algorithm ${security.level1KeyAlg}`);
  }

  const componentLength = curveComponentLength(curve);
  const rawSig = derToRaw(security.level1Signature, componentLength);
  const ops = getCurveOps(curve);
  const msgHash = ops.hash(extracted.level1DataBytes);

  return {
    label,
    provider: security.securityProviderNum ?? 0,
    keyId: security.keyId ?? 0,
    curve,
    sigAlg: `ECDSA ${curve} with ${sigAlg.hash}`,
    level1DataBytes: extracted.level1DataBytes,
    rawSig,
    msgHash,
  };
}

function recoverCandidates(ticket: TicketInfo): Uint8Array[] {
  const ops = getCurveOps(ticket.curve);
  const sigObj = ops.signatureFromBytes(ticket.rawSig);
  const candidates: Uint8Array[] = [];

  for (const recovery of [0, 1]) {
    try {
      const recovered = sigObj.addRecoveryBit(recovery).recoverPublicKey(ticket.msgHash);
      const pkBytes = recovered.toBytes();
      // Verify the candidate actually works
      if (ops.verify(ticket.rawSig, ticket.level1DataBytes, pkBytes)) {
        candidates.push(pkBytes);
      }
    } catch {
      // Recovery bit may not yield a valid point — skip
    }
  }

  return candidates;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args[0] === '--help' || args[0] === '-h') {
    console.log('Usage: npx tsx cli/extract-ecdsa-key.ts <ticket1> [ticket2] [...]');
    console.log();
    console.log('Extract ECDSA Level 1 public keys from UIC barcode ticket signatures.');
    console.log('A single ticket yields two candidate keys; additional tickets signed');
    console.log('with the same key narrow the result to the real key.');
    console.log();
    console.log('Each argument can be:');
    console.log('  A fixture name: sample, sncf, solea, cts, grand_est, ardeche, ain, drome');
    console.log('  A path to a .hex file');
    console.log('  Inline hex data');
    process.exit(0);
  }

  // Resolve inputs
  const tickets: TicketInfo[] = [];
  for (const input of args) {
    let hex: string;
    let label: string;

    if (FIXTURES[input.toLowerCase()]) {
      hex = FIXTURES[input.toLowerCase()];
      label = input.toLowerCase();
    } else if (fs.existsSync(input)) {
      hex = fs.readFileSync(input, 'utf-8').trim();
      label = input;
    } else if (/^[0-9a-fA-F\s]+h?$/.test(input.trim())) {
      hex = input;
      label = `inline(${input.substring(0, 16)}...)`;
    } else {
      fail(`Unknown input: ${input}`);
      process.exit(1);
    }

    try {
      tickets.push(extractTicketInfo(label, hex));
    } catch (e: unknown) {
      fail(e instanceof Error ? e.message : `Failed to process ${label}`);
      process.exit(1);
    }
  }

  // Display ticket info
  heading('Tickets');
  for (const t of tickets) {
    console.log(`  ${BOLD}${t.label}${RESET}`);
    console.log(`    ${DIM}provider:${RESET} ${t.provider}  ${DIM}keyId:${RESET} ${t.keyId}  ${DIM}algorithm:${RESET} ${t.sigAlg}`);
  }

  // Check all tickets share the same provider/keyId/curve
  const ref = tickets[0];
  const mismatch = tickets.find(t =>
    t.provider !== ref.provider || t.keyId !== ref.keyId || t.curve !== ref.curve
  );
  if (mismatch) {
    warn(`Ticket "${mismatch.label}" has different provider/keyId/curve than "${ref.label}".`);
    warn(`  ${ref.label}: provider=${ref.provider} keyId=${ref.keyId} curve=${ref.curve}`);
    warn(`  ${mismatch.label}: provider=${mismatch.provider} keyId=${mismatch.keyId} curve=${mismatch.curve}`);
    warn('Proceeding anyway — intersection may be empty.');
  }

  // Recover candidates from each ticket
  heading('Recovery');
  const candidateSets: string[][] = [];

  for (const t of tickets) {
    const candidates = recoverCandidates(t);
    const hexCandidates = candidates.map(c => toHex(c));
    candidateSets.push(hexCandidates);

    ok(`${t.label}: ${candidates.length} candidate(s)`);
    for (let i = 0; i < candidates.length; i++) {
      console.log(`    ${DIM}[${i}]${RESET} ${hexCandidates[i]}`);
    }
  }

  // Intersect candidate sets
  heading('Result');

  let commonKeys = new Set(candidateSets[0]);
  for (let i = 1; i < candidateSets.length; i++) {
    const nextSet = new Set(candidateSets[i]);
    commonKeys = new Set([...commonKeys].filter(k => nextSet.has(k)));
  }

  if (commonKeys.size === 0) {
    fail('No common public key found across all tickets.');
    process.exit(1);
  }

  const keys = [...commonKeys];
  if (keys.length === 1) {
    ok(`Found unique public key for provider ${ref.provider}, key ID ${ref.keyId} (${ref.curve}):`);
  } else {
    warn(`Found ${keys.length} candidate key(s) — provide more tickets to disambiguate:`);
  }

  for (const key of keys) {
    console.log(`\n  ${GREEN}${key}${RESET}`);

    // Verify against all tickets
    const keyBytes = hexToBytes(key);
    const ops = getCurveOps(ref.curve);
    let allValid = true;
    for (const t of tickets) {
      const valid = ops.verify(t.rawSig, t.level1DataBytes, keyBytes);
      if (valid) {
        ok(`Verified against ${t.label}`);
      } else {
        fail(`FAILED against ${t.label}`);
        allValid = false;
      }
    }
    if (allValid && tickets.length > 1) {
      ok(`Key verified against all ${tickets.length} tickets`);
    }
  }

  console.log();
}

main();
