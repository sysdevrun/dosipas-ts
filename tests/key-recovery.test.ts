import {
  recoverLevel1PublicKey,
  decodeTicket,
  encodeTicketToBytes,
  signAndEncodeTicket,
  generateKeyPair,
  getPublicKey,
  verifyLevel1Signature,
  SOLEA_TICKET_HEX,
  CTS_TICKET_HEX,
  SNCF_TER_TICKET_HEX,
  CAR_JAUNE_TICKET_HEX,
  CAR_JAUNE_SIGNATURES,
} from '../src';
import type { SigningKeyPair, UicBarcodeTicket } from '../src';

/** NIST FIPS 186-4 ECDSA P-256 test vector private keys. */
const FIPS_L1_PRIV = hexToBytes('c9806898a0334916c860748880a541f093b579a9b1f32934d86c363c39800357');
const FIPS_L2_PRIV = hexToBytes('710735c8388f48c684a97bd66751cc5f5a122d6b9a96a2dbe73662f78217446d');

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(hex.match(/.{1,2}/g)!.map(b => parseInt(b, 16)));
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function makeKeyPair(privateKey: Uint8Array, curve: 'P-256' | 'P-384' | 'P-521'): SigningKeyPair {
  return {
    privateKey,
    publicKey: getPublicKey(privateKey, curve),
    curve,
  };
}

/** Re-sign a decoded fixture ticket with the given key pair. */
function resign(ticketHex: string, l1Key: SigningKeyPair): Uint8Array {
  const ticket = decodeTicket(ticketHex);
  const l2Key = generateKeyPair(l1Key.curve);
  return signAndEncodeTicket(ticket, l1Key, l2Key);
}

// ---------------------------------------------------------------------------
// Real-world tickets
// ---------------------------------------------------------------------------

describe('recoverLevel1PublicKey on real tickets', () => {
  it('recovers the unique Soléa/CTS shared key from the two tickets', async () => {
    // Both tickets are signed with the same level 1 key (RICS 1187, keyId 1)
    // and carry their algorithm OIDs, so no options are needed.
    const solea = hexToBytes(SOLEA_TICKET_HEX);
    const cts = hexToBytes(CTS_TICKET_HEX);

    const candidates = recoverLevel1PublicKey([solea, cts]);
    expect(candidates).toHaveLength(1);

    // The recovered key verifies both tickets.
    const key = { publicKey: candidates[0] };
    expect((await verifyLevel1Signature(solea, key)).valid).toBe(true);
    expect((await verifyLevel1Signature(cts, key)).valid).toBe(true);
  });

  it('yields the true key among the candidates from a single ticket', () => {
    const solea = hexToBytes(SOLEA_TICKET_HEX);
    const cts = hexToBytes(CTS_TICKET_HEX);

    const fromSolea = recoverLevel1PublicKey([solea]).map(bytesToHex);
    const fromCts = recoverLevel1PublicKey([cts]).map(bytesToHex);

    // Each single signature yields the two usual candidates...
    expect(fromSolea).toHaveLength(2);
    expect(fromCts).toHaveLength(2);

    // ...and the true key is the one they share.
    const shared = fromSolea.filter(c => fromCts.includes(c));
    expect(shared).toHaveLength(1);
  });

  it('recovers the documented Car Jaune key using configured OIDs', async () => {
    // The Car Jaune barcode carries no algorithm OIDs — supply them, exactly
    // as for verification.
    const carJaune = hexToBytes(CAR_JAUNE_TICKET_HEX);
    const candidates = recoverLevel1PublicKey([carJaune], {
      keyAlg: CAR_JAUNE_SIGNATURES.level1KeyAlg,
      signingAlg: CAR_JAUNE_SIGNATURES.level1SigningAlg,
    });

    expect(candidates).toHaveLength(2);
    const hexes = candidates.map(bytesToHex);
    expect(hexes).toContain(CAR_JAUNE_SIGNATURES.level1PublicKeyHex);

    // The documented candidate verifies the ticket.
    const documented = candidates.find(
      c => bytesToHex(c) === CAR_JAUNE_SIGNATURES.level1PublicKeyHex,
    )!;
    const result = await verifyLevel1Signature(carJaune, {
      publicKey: documented,
      keyAlg: CAR_JAUNE_SIGNATURES.level1KeyAlg,
      signingAlg: CAR_JAUNE_SIGNATURES.level1SigningAlg,
    });
    expect(result.valid).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Synthetic tickets (known keys)
// ---------------------------------------------------------------------------

describe('recoverLevel1PublicKey on re-signed tickets', () => {
  it('recovers exactly the signing key from two P-256 tickets', () => {
    const l1Key = makeKeyPair(FIPS_L1_PRIV, 'P-256');
    const tickets = [resign(SOLEA_TICKET_HEX, l1Key), resign(CTS_TICKET_HEX, l1Key)];

    const candidates = recoverLevel1PublicKey(tickets);
    expect(candidates).toHaveLength(1);
    expect(bytesToHex(candidates[0])).toBe(bytesToHex(l1Key.publicKey));
  });

  it.each(['P-384', 'P-521'] as const)('recovers the signing key on %s', curve => {
    const l1Key = generateKeyPair(curve);
    const tickets = [resign(SOLEA_TICKET_HEX, l1Key), resign(CTS_TICKET_HEX, l1Key)];

    const candidates = recoverLevel1PublicKey(tickets);
    expect(candidates).toHaveLength(1);
    expect(bytesToHex(candidates[0])).toBe(bytesToHex(l1Key.publicKey));
  });

  it('includes the signing key among the candidates from a single ticket', () => {
    const l1Key = makeKeyPair(FIPS_L1_PRIV, 'P-256');
    const candidates = recoverLevel1PublicKey([resign(SOLEA_TICKET_HEX, l1Key)]);

    expect(candidates.length).toBeGreaterThanOrEqual(1);
    expect(candidates.length).toBeLessThanOrEqual(4);
    expect(candidates.map(bytesToHex)).toContain(bytesToHex(l1Key.publicKey));
  });

  it('returns an empty array for tickets signed with different keys', () => {
    const keyA = makeKeyPair(FIPS_L1_PRIV, 'P-256');
    const keyB = makeKeyPair(FIPS_L2_PRIV, 'P-256');
    const tickets = [resign(SOLEA_TICKET_HEX, keyA), resign(CTS_TICKET_HEX, keyB)];

    expect(recoverLevel1PublicKey(tickets)).toEqual([]);
  });

  it('narrows but never drops the true key as tickets are added', () => {
    const l1Key = makeKeyPair(FIPS_L1_PRIV, 'P-256');
    const t1 = resign(SOLEA_TICKET_HEX, l1Key);
    const t2 = resign(CTS_TICKET_HEX, l1Key);

    const one = recoverLevel1PublicKey([t1]).map(bytesToHex);
    const two = recoverLevel1PublicKey([t1, t2]).map(bytesToHex);

    expect(one).toContain(bytesToHex(l1Key.publicKey));
    expect(two).toEqual([bytesToHex(l1Key.publicKey)]);
    // Every survivor of the pair was already a candidate of the single ticket.
    for (const c of two) expect(one).toContain(c);
  });
});

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

describe('recoverLevel1PublicKey errors', () => {
  it('rejects an empty ticket list', () => {
    expect(() => recoverLevel1PublicKey([])).toThrow('At least one ticket');
  });

  it('rejects a barcode without OIDs when none are configured', () => {
    const carJaune = hexToBytes(CAR_JAUNE_TICKET_HEX);
    expect(() => recoverLevel1PublicKey([carJaune])).toThrow(
      /Ticket #0: Missing level 1 signing algorithm/,
    );
  });

  it('rejects non-ECDSA level 1 signatures', () => {
    // The SNCF TER ticket's level 1 signature is DSA (OID shared out of band,
    // like the rest of its algorithm metadata).
    const ter = hexToBytes(SNCF_TER_TICKET_HEX);
    expect(() =>
      recoverLevel1PublicKey([ter], { signingAlg: '2.16.840.1.101.3.4.3.1' }),
    ).toThrow(/Ticket #0: public key recovery requires ECDSA.*DSA/);
  });

  it('rejects tickets that resolve to different curves', () => {
    const t256 = resign(SOLEA_TICKET_HEX, makeKeyPair(FIPS_L1_PRIV, 'P-256'));
    const t384 = resign(CTS_TICKET_HEX, generateKeyPair('P-384'));

    expect(() => recoverLevel1PublicKey([t256, t384])).toThrow(
      /Ticket #1: .*P-384.*ticket #0.*P-256/,
    );
  });

  it('rejects a mismatch between the barcode OIDs and the configured ones', () => {
    const solea = hexToBytes(SOLEA_TICKET_HEX);
    expect(() =>
      recoverLevel1PublicKey([solea], { keyAlg: '1.3.132.0.34' /* P-384 */ }),
    ).toThrow(/Ticket #0: .*mismatch/);
  });

  it('rejects undecodable ticket bytes with the ticket index', () => {
    expect(() => recoverLevel1PublicKey([new Uint8Array([1, 2, 3])])).toThrow(/Ticket #0:/);
  });

  it('rejects a ticket without a level 1 signature', () => {
    // Re-encode Soléa with its level 1 signature stripped.
    const ticket = decodeTicket(SOLEA_TICKET_HEX);
    const noSig: UicBarcodeTicket = {
      ...ticket,
      level2SignedData: { ...ticket.level2SignedData, level1Signature: undefined },
    };
    const bytes = encodeTicketToBytes(noSig);

    expect(() => recoverLevel1PublicKey([bytes])).toThrow(
      'Ticket #0: missing level 1 signature',
    );
  });
});
