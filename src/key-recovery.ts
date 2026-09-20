/**
 * ECDSA public key recovery from observed UIC barcode tickets.
 *
 * An ECDSA signature does not include the signer's public key, but the key
 * can be *recovered* from the signature and the signed data — up to a small
 * set of candidates (usually two). Each ticket narrows the set: the true key
 * is a candidate for every ticket of the batch, while the spurious candidates
 * differ from one signature to the next. In practice the intersection across
 * two tickets is already unique.
 *
 * This is how the Car Jaune level 1 key in `signature-fixtures.ts` was
 * obtained: its issuer identifies itself with an IA5 string, so the key is
 * not in the UIC public key registry, and it was recovered from six observed
 * tickets of one batch instead.
 *
 * Recovering a public key discloses no secret — it computes something any
 * verifier of the batch could compute.
 */
import { p256, p384, p521 } from '@noble/curves/nist.js';
import { sha256, sha384, sha512 } from '@noble/hashes/sha2.js';

import { toExtractedTicket } from './signed-data.js';
import type { ExtractedTicket } from './signed-data.js';
import { resolveAlgorithms, curveComponentLength } from './oids.js';
import { derToRaw } from './signature-utils.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Options for {@link recoverLevel1PublicKey}. Same semantics and accepted
 * values as the matching fields on `Level1KeyMaterial`: used only when the
 * barcode carries no OID of its own, and a disagreement with the barcode is
 * an error rather than a silent preference.
 */
export interface RecoverLevel1KeyOptions {
  /**
   * Key algorithm OID (identifies the curve), e.g. `'1.2.840.10045.3.1.7'`
   * for P-256. Accepted values are the keys of `KEY_ALGORITHMS` in
   * `src/oids.ts`.
   */
  keyAlg?: string;
  /**
   * Signing algorithm OID (identifies the hash), e.g. `'1.2.840.10045.4.3.2'`
   * for ECDSA with SHA-256. Accepted values are the keys of
   * `SIGNING_ALGORITHMS` in `src/oids.ts`.
   */
  signingAlg?: string;
}

// ---------------------------------------------------------------------------
// Curve / hash dispatch
// ---------------------------------------------------------------------------

type CurveInstance = typeof p256;

function getCurveInstance(curve: string): CurveInstance {
  switch (curve) {
    case 'P-256': return p256;
    case 'P-384': return p384;
    case 'P-521': return p521;
    default: throw new Error(`Unsupported curve: ${curve}`);
  }
}

const HASHES: Record<string, (msg: Uint8Array) => Uint8Array> = {
  'SHA-256': sha256,
  'SHA-384': sha384,
  'SHA-512': sha512,
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Recover the Level 1 public key from one or more observed tickets signed
 * with the same key.
 *
 * Each ticket's signature yields a handful of candidate keys (two in the
 * typical case); candidates that are not shared by *every* ticket are
 * discarded. Every returned candidate verifies the Level 1 signature of all
 * supplied tickets, so:
 *
 * - with a single ticket, expect two candidates — the true key and a spurious
 *   one that happens to verify that one signature;
 * - with two or more tickets carrying distinct signatures, expect exactly one
 *   candidate — the issuer's key;
 * - an empty result means the tickets were not all signed with the same key.
 *
 * Algorithm resolution follows the same rules as verification: the OIDs in
 * the barcode take precedence, then the configured `options`, and a
 * disagreement is an error. For barcodes that omit their OIDs (e.g. the Car
 * Jaune fixture), pass them via `options`. All tickets must resolve to the
 * same ECDSA curve and hash.
 *
 * @param tickets - The observed tickets: raw payload bytes, or extracted
 *   tickets (e.g. a signature group's `tickets`).
 * @param options - Algorithm OIDs to use when the barcodes omit their own.
 * @returns Candidate public keys as uncompressed EC points (0x04 || x || y).
 * @throws When no ticket is supplied, a ticket cannot be processed, the
 *   algorithms cannot be resolved, or the tickets resolve to different
 *   algorithms.
 */
export function recoverLevel1PublicKey(
  tickets: Array<Uint8Array | ExtractedTicket>,
  options?: RecoverLevel1KeyOptions,
): Uint8Array[] {
  if (tickets.length === 0) {
    throw new Error('At least one ticket is required to recover a public key');
  }

  // Candidate keys as hex strings, for set intersection across tickets.
  let candidates: string[] | undefined;
  // (curve, hash) of the first ticket — all tickets must agree.
  let firstAlgorithms: { curve: string; hash: string; description: string } | undefined;

  for (let i = 0; i < tickets.length; i++) {
    let ticketCandidates: Set<string>;
    try {
      const { level1 } = toExtractedTicket(tickets[i]);

      if (!level1.signature) {
        throw new Error('missing level 1 signature');
      }

      const resolved = resolveAlgorithms({
        level: 1,
        barcodeSigningAlg: level1.signingAlg,
        barcodeKeyAlg: level1.keyAlg,
        configuredSigningAlg: options?.signingAlg,
        configuredKeyAlg: options?.keyAlg,
      });
      if (!resolved.ok) throw new Error(resolved.error);

      if (resolved.signing.type !== 'ECDSA') {
        throw new Error(
          `public key recovery requires ECDSA, got ${resolved.description}`,
        );
      }

      // `curve` is guaranteed present for ECDSA by resolveAlgorithms.
      const curve = resolved.curve!;
      const hashName = resolved.signing.hash;
      if (firstAlgorithms === undefined) {
        firstAlgorithms = { curve, hash: hashName, description: resolved.description };
      } else if (firstAlgorithms.curve !== curve || firstAlgorithms.hash !== hashName) {
        throw new Error(
          `resolves to ${resolved.description}, but ticket #0 resolves to ` +
          `${firstAlgorithms.description}. All tickets must be signed with ` +
          `the same key, so with the same algorithms.`,
        );
      }

      const hash = HASHES[hashName];
      if (!hash) {
        throw new Error(`unsupported hash for public key recovery: ${hashName}`);
      }

      ticketCandidates = recoverCandidates(
        level1.signedBytes,
        level1.signature,
        curve,
        hash,
      );
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'unknown error';
      throw new Error(`Ticket #${i}: ${msg}`);
    }

    candidates = candidates === undefined
      ? [...ticketCandidates]
      : candidates.filter(c => ticketCandidates.has(c));

    // The intersection can only shrink — stop early once it is empty.
    if (candidates.length === 0) return [];
  }

  return candidates!.map(hexToBytes);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Recover all candidate public keys for one signature, as a set of
 * uncompressed-point hex strings.
 *
 * ECDSA recovery is parameterized by a recovery bit; bits 0 and 1 select the
 * candidate points in the common case, while 2 and 3 only apply in the
 * astronomically rare case where r exceeds the curve order. Bits that do not
 * produce a valid point are skipped.
 */
function recoverCandidates(
  signedData: Uint8Array,
  derSignature: Uint8Array,
  curve: string,
  hash: (msg: Uint8Array) => Uint8Array,
): Set<string> {
  const c = getCurveInstance(curve);
  const rawSig = derToRaw(derSignature, curveComponentLength(curve));
  const signature = c.Signature.fromBytes(rawSig);
  const msgHash = hash(signedData);

  const candidates = new Set<string>();
  for (let bit = 0; bit < 4; bit++) {
    try {
      const point = signature.addRecoveryBit(bit).recoverPublicKey(msgHash);
      candidates.add(bytesToHex(point.toBytes(false)));
    } catch {
      // This recovery bit does not yield a valid curve point — skip it.
    }
  }
  return candidates;
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex;
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
