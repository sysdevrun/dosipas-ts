/**
 * Signature collection from scanned UIC barcodes.
 *
 * When scanning many QR codes (e.g. with a camera in a control app), each
 * scan yields a raw barcode payload. The collector extracts each payload via
 * {@link extractTicket} and classifies it automatically by Level 1 key
 * identity ({@link SignatureKey}: issuer + keyId), deduplicating repeated
 * scans of the same barcode along the way. Unreadable scans are expected
 * input in a camera loop, so `add` reports them as a result instead of
 * throwing.
 *
 * Groups store the canonical {@link ExtractedTicket} records, so they plug
 * directly into the rest of the library: `findKeyInXml(xml, group.key)` looks
 * the key up in the UIC registry, `recoverLevel1PublicKey(group.tickets)`
 * recovers it from the observed tickets when it is not published, and
 * `verifySignatures(ticket, options)` verifies without re-decoding.
 */
import {
  extractTicket,
  toExtractedTicket,
  type ExtractedTicket,
  type SignatureKey,
} from './signed-data.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Tickets sharing one Level 1 key identity (issuer + keyId). */
export interface SignatureGroup {
  /** The shared key identity. `key.id` is the display label (e.g. "1187/1"). */
  key: SignatureKey;
  /** Distinct collected tickets, in scan order. */
  tickets: ExtractedTicket[];
}

/** Result of feeding one scan to {@link SignatureCollector.add}. */
export type AddResult =
  /** A new ticket, classified into `group` (a live object, updated in place). */
  | { status: 'added'; group: SignatureGroup; ticket: ExtractedTicket }
  /** This exact payload was already collected — nothing changed. */
  | { status: 'duplicate'; group: SignatureGroup; ticket: ExtractedTicket }
  /** The payload is not a decodable UIC barcode — nothing changed. */
  | { status: 'invalid'; error: Error };

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
 *   const result = collector.add(payload);
 *   if (result.status === 'added') console.log(`ticket for key ${result.group.key.id}`);
 * }
 * const groups = collector.groups();
 * ```
 */
export class SignatureCollector {
  private readonly groupsByKey = new Map<string, SignatureGroup>();
  private readonly resultsByPayload = new Map<string, AddResult & { status: 'added' }>();

  /**
   * Classify one scan.
   *
   * Accepts raw payload bytes or an already-extracted ticket (to avoid
   * decoding twice when the scan was extracted for verification). Rescans of
   * an already-collected payload are detected byte-for-byte and reported as
   * `'duplicate'` without growing any group; undecodable payloads are
   * reported as `'invalid'`.
   */
  add(input: Uint8Array | ExtractedTicket): AddResult {
    let ticket: ExtractedTicket;
    try {
      ticket = toExtractedTicket(input);
    } catch (e: unknown) {
      return {
        status: 'invalid',
        error: e instanceof Error ? e : new Error('unknown extraction error'),
      };
    }

    const payloadHex = bytesToHex(ticket.bytes);
    const seen = this.resultsByPayload.get(payloadHex);
    if (seen) {
      return { ...seen, status: 'duplicate' };
    }

    let group = this.groupsByKey.get(mapKeyOf(ticket.key));
    if (!group) {
      group = { key: ticket.key, tickets: [] };
      this.groupsByKey.set(mapKeyOf(ticket.key), group);
    }
    group.tickets.push(ticket);

    const result = { status: 'added' as const, group, ticket };
    this.resultsByPayload.set(payloadHex, result);
    return result;
  }

  /**
   * All groups collected so far, sorted for stable display: numeric issuers
   * first in ascending order, then IA5 issuers alphabetically, then by keyId.
   */
  groups(): SignatureGroup[] {
    return [...this.groupsByKey.values()].sort(compareGroups);
  }

  /**
   * Look one group up by its key, or by its canonical `id` label. On the
   * rare label collision (a purely numeric IA5 issuer), a string matches the
   * numeric-issuer group first; pass a {@link SignatureKey} to be exact.
   */
  group(key: SignatureKey | string): SignatureGroup | undefined {
    if (typeof key !== 'string') return this.groupsByKey.get(mapKeyOf(key));
    return this.groups().find(g => g.key.id === key);
  }

  /** Number of distinct tickets collected (duplicates excluded). */
  get size(): number {
    return this.resultsByPayload.size;
  }
}

/**
 * Classify a batch of payloads by Level 1 key identity in one call.
 *
 * Convenience wrapper over {@link SignatureCollector} for when all scans are
 * already in hand. Duplicated payloads are collected once. Unlike the
 * collector's `add`, an undecodable payload here is a programming error, so
 * it throws, naming the payload's index.
 *
 * @param payloads - Raw payload bytes (or extracted tickets) of each scan.
 * @returns Signature groups, sorted as {@link SignatureCollector.groups}.
 */
export function collectSignatures(
  payloads: Iterable<Uint8Array | ExtractedTicket>,
): SignatureGroup[] {
  const collector = new SignatureCollector();
  let i = 0;
  for (const payload of payloads) {
    const result = collector.add(payload);
    if (result.status === 'invalid') {
      throw new Error(`Payload #${i}: ${result.error.message}`);
    }
    i++;
  }
  return collector.groups();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Grouping key: unlike `key.id`, it cannot collide between a numeric issuer
 * and an IA5 issuer that spells the same number.
 */
function mapKeyOf(key: SignatureKey): string {
  const issuer = key.securityProviderNum != null
    ? `n:${key.securityProviderNum}`
    : `i:${key.securityProviderIA5 ?? ''}`;
  return `${issuer}|${key.keyId ?? ''}`;
}

function compareGroups(a: SignatureGroup, b: SignatureGroup): number {
  const aNum = a.key.securityProviderNum;
  const bNum = b.key.securityProviderNum;
  if (aNum != null && bNum != null && aNum !== bNum) return aNum - bNum;
  if ((aNum != null) !== (bNum != null)) return aNum != null ? -1 : 1;
  const aIa5 = a.key.securityProviderIA5 ?? '';
  const bIa5 = b.key.securityProviderIA5 ?? '';
  if (aIa5 !== bIa5) return aIa5 < bIa5 ? -1 : 1;
  return (a.key.keyId ?? -1) - (b.key.keyId ?? -1);
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex;
}
