/**
 * Signature collection from scanned UIC barcodes.
 *
 * When scanning many QR codes (e.g. with a camera in a control app), each
 * scan yields a raw barcode payload. The collector extracts each payload's
 * signatures via {@link extractSignedData} and classifies them automatically
 * by Level 1 key identity — issuer (`securityProviderNum` or
 * `securityProviderIA5`) plus `keyId` — deduplicating repeated scans of the
 * same barcode along the way.
 *
 * The resulting groups plug directly into the rest of the library:
 * `findKeyInXml(xml, group.securityProviderNum, group.keyId)` looks the key
 * up in the UIC registry, and `recoverLevel1PublicKey(group.tickets.map(t =>
 * t.bytes))` recovers it from the observed tickets when it is not published.
 */
import { extractSignedData } from './signed-data.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** One collected ticket: its payload and the signatures extracted from it. */
export interface CollectedTicket {
  /** Raw barcode payload bytes, exactly as scanned. */
  bytes: Uint8Array;
  /** Level 1 signature (DER), absent when the barcode carries none. */
  level1Signature?: Uint8Array;
  /** Level 2 signature (DER), absent for static barcodes. */
  level2Signature?: Uint8Array;
  /** Level 1 key algorithm OID, when the barcode carries one. */
  level1KeyAlg?: string;
  /** Level 1 signing algorithm OID, when the barcode carries one. */
  level1SigningAlg?: string;
}

/** Tickets sharing one Level 1 key identity (issuer + keyId). */
export interface SignatureGroup {
  /**
   * Canonical group label: `"<issuer>/<keyId>"`, where issuer is the RICS
   * code or the IA5 string (`"1187/1"`, `"IWN8/1"`). A missing part reads
   * `"?"`. For display; group identity is the three fields below.
   */
  id: string;
  /** Issuer RICS code, when the barcode identifies its issuer numerically. */
  securityProviderNum?: number;
  /** Issuer IA5 string, when the barcode identifies its issuer as text. */
  securityProviderIA5?: string;
  /** Key identifier within the issuer's key set. */
  keyId?: number;
  /** Distinct collected tickets, in scan order. */
  tickets: CollectedTicket[];
}

/** Result of feeding one scan to {@link SignatureCollector.add}. */
export interface AddScanResult {
  /** The group the scan was classified into (live object, updated in place). */
  group: SignatureGroup;
  /** The collected ticket record for this payload. */
  ticket: CollectedTicket;
  /** True when this exact payload had already been collected (rescan). */
  duplicate: boolean;
}

// ---------------------------------------------------------------------------
// Collector
// ---------------------------------------------------------------------------

/**
 * Accumulates scanned barcode payloads and classifies their signatures by
 * Level 1 key identity (issuer + keyId).
 *
 * ```ts
 * const collector = new SignatureCollector();
 * for (const payload of scans) {
 *   try {
 *     const { group, duplicate } = collector.add(payload);
 *     if (!duplicate) console.log(`ticket for key ${group.id}`);
 *   } catch {
 *     // not a decodable UIC barcode — ignore the scan
 *   }
 * }
 * const groups = collector.groups();
 * ```
 */
export class SignatureCollector {
  private readonly groupsByKey = new Map<string, SignatureGroup>();
  private readonly ticketsByPayload = new Map<string, AddScanResult>();

  /**
   * Classify one scanned payload.
   *
   * Rescans of an already-collected payload are detected byte-for-byte and
   * reported with `duplicate: true` without growing any group.
   *
   * @param bytes - Raw barcode payload bytes.
   * @returns The group the payload belongs to and its ticket record.
   * @throws When the payload is not a decodable UIC barcode.
   */
  add(bytes: Uint8Array): AddScanResult {
    const payloadHex = bytesToHex(bytes);
    const seen = this.ticketsByPayload.get(payloadHex);
    if (seen) {
      return { ...seen, duplicate: true };
    }

    const { security } = extractSignedData(bytes);
    const { securityProviderNum, securityProviderIA5, keyId } = security;

    // Disambiguate numeric and IA5 issuers (an IA5 issuer could spell a number).
    const mapKey =
      (securityProviderNum != null ? `n:${securityProviderNum}` : `i:${securityProviderIA5 ?? ''}`) +
      `|${keyId ?? ''}`;

    let group = this.groupsByKey.get(mapKey);
    if (!group) {
      group = {
        id: `${securityProviderNum ?? securityProviderIA5 ?? '?'}/${keyId ?? '?'}`,
        securityProviderNum,
        securityProviderIA5,
        keyId,
        tickets: [],
      };
      this.groupsByKey.set(mapKey, group);
    }

    const ticket: CollectedTicket = {
      bytes,
      level1Signature: security.level1Signature,
      level2Signature: security.level2Signature,
      level1KeyAlg: security.level1KeyAlg,
      level1SigningAlg: security.level1SigningAlg,
    };
    group.tickets.push(ticket);

    const result: AddScanResult = { group, ticket, duplicate: false };
    this.ticketsByPayload.set(payloadHex, result);
    return result;
  }

  /**
   * All groups collected so far, sorted for stable display: numeric issuers
   * first in ascending order, then IA5 issuers alphabetically, then by keyId.
   */
  groups(): SignatureGroup[] {
    return [...this.groupsByKey.values()].sort(compareGroups);
  }

  /** Number of distinct tickets collected (duplicates excluded). */
  get size(): number {
    return this.ticketsByPayload.size;
  }
}

/**
 * Classify a batch of payloads by Level 1 key identity in one call.
 *
 * Convenience wrapper over {@link SignatureCollector} for when all scans are
 * already in hand. Duplicated payloads are collected once.
 *
 * @param payloads - Raw barcode payload bytes of each scan.
 * @returns Signature groups, sorted as {@link SignatureCollector.groups}.
 * @throws When a payload is not a decodable UIC barcode, naming its index.
 */
export function collectSignatures(payloads: Iterable<Uint8Array>): SignatureGroup[] {
  const collector = new SignatureCollector();
  let i = 0;
  for (const payload of payloads) {
    try {
      collector.add(payload);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'unknown error';
      throw new Error(`Payload #${i}: ${msg}`);
    }
    i++;
  }
  return collector.groups();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function compareGroups(a: SignatureGroup, b: SignatureGroup): number {
  const aNum = a.securityProviderNum;
  const bNum = b.securityProviderNum;
  if (aNum != null && bNum != null && aNum !== bNum) return aNum - bNum;
  if ((aNum != null) !== (bNum != null)) return aNum != null ? -1 : 1;
  const aIa5 = a.securityProviderIA5 ?? '';
  const bIa5 = b.securityProviderIA5 ?? '';
  if (aIa5 !== bIa5) return aIa5 < bIa5 ? -1 : 1;
  return (a.keyId ?? -1) - (b.keyId ?? -1);
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex;
}
