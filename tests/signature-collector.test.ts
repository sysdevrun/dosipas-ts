import { describe, it, expect } from 'vitest';

import {
  SignatureCollector,
  collectSignatures,
  extractTicket,
  signatureKey,
  SAMPLE_TICKET_HEX,
  SNCF_TER_TICKET_HEX,
  SOLEA_TICKET_HEX,
  CTS_TICKET_HEX,
  BUS_ARDECHE_TICKET_HEX,
  BUS_AIN_TICKET_HEX,
  DROME_BUS_TICKET_HEX,
  GRAND_EST_U1_FCB3_HEX,
  CAR_JAUNE_TICKET_HEX,
  SOLEA_SIGNATURES,
  CAR_JAUNE_SIGNATURES,
} from '../src';

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex;
}

const ALL_TICKETS_HEX = [
  SAMPLE_TICKET_HEX,
  SNCF_TER_TICKET_HEX,
  SOLEA_TICKET_HEX,
  CTS_TICKET_HEX,
  BUS_ARDECHE_TICKET_HEX,
  BUS_AIN_TICKET_HEX,
  DROME_BUS_TICKET_HEX,
  GRAND_EST_U1_FCB3_HEX,
  CAR_JAUNE_TICKET_HEX,
];

describe('SignatureCollector', () => {
  it('classifies scans by issuer and keyId', () => {
    const collector = new SignatureCollector();
    for (const hex of ALL_TICKETS_HEX) {
      expect(collector.add(hexToBytes(hex)).status).toBe('added');
    }

    const groups = collector.groups();
    expect(groups.map(g => g.key.id)).toEqual([
      '1187/0',   // SNCF TER
      '3703/1',   // sample ticket
      '3703/2',   // Grand Est
      '3703/7',   // Soléa + CTS share one key
      '5152/3',   // the three bus networks share one key
      'IWN8/1',   // Car Jaune (IA5 issuer)
    ]);
    expect(groups.map(g => g.tickets.length)).toEqual([1, 1, 1, 2, 3, 1]);
    expect(collector.size).toBe(9);
  });

  it('exposes the key identity on each group', () => {
    const collector = new SignatureCollector();
    collector.add(hexToBytes(SOLEA_TICKET_HEX));
    collector.add(hexToBytes(CAR_JAUNE_TICKET_HEX));

    const [solea, carJaune] = collector.groups();
    expect(solea.key.securityProviderNum).toBe(3703);
    expect(solea.key.securityProviderIA5).toBeUndefined();
    expect(solea.key.keyId).toBe(7);
    expect(carJaune.key.securityProviderNum).toBeUndefined();
    expect(carJaune.key.securityProviderIA5).toBe(CAR_JAUNE_SIGNATURES.securityProviderIA5);
    expect(carJaune.key.keyId).toBe(CAR_JAUNE_SIGNATURES.keyId);
  });

  it('stores the full extracted ticket in each group', () => {
    const collector = new SignatureCollector();
    const result = collector.add(hexToBytes(SOLEA_TICKET_HEX));
    if (result.status !== 'added') throw new Error(`unexpected status ${result.status}`);

    const { ticket } = result;
    expect(bytesToHex(ticket.level1.signature!)).toBe(SOLEA_SIGNATURES.level1SignatureHex);
    expect(ticket.level1.keyAlg).toBe(SOLEA_SIGNATURES.level1KeyAlg);
    expect(ticket.level1.signingAlg).toBe(SOLEA_SIGNATURES.level1SigningAlg);
    expect(ticket.level1.signedBytes.length).toBeGreaterThan(0);
    // Level 2 is carried in full too: signature, signed bytes and public key.
    expect(ticket.level2.signature![0]).toBe(0x30);
    expect(ticket.level2.signedBytes.length).toBeGreaterThan(ticket.level1.signedBytes.length);
    expect(ticket.level2.publicKey).toBeDefined();
  });

  it('accepts an already-extracted ticket', () => {
    const collector = new SignatureCollector();
    const ticket = extractTicket(hexToBytes(SOLEA_TICKET_HEX));

    const result = collector.add(ticket);
    if (result.status !== 'added') throw new Error(`unexpected status ${result.status}`);
    expect(result.ticket).toBe(ticket);

    // The same payload as raw bytes is a duplicate of the extracted ticket.
    expect(collector.add(hexToBytes(SOLEA_TICKET_HEX)).status).toBe('duplicate');
  });

  it('leaves level2 signature undefined for static barcodes', () => {
    const collector = new SignatureCollector();
    const result = collector.add(hexToBytes(CAR_JAUNE_TICKET_HEX));
    if (result.status !== 'added') throw new Error(`unexpected status ${result.status}`);

    expect(result.ticket.level2.signature).toBeUndefined();
    expect(bytesToHex(result.ticket.level1.signature!)).toBe(CAR_JAUNE_SIGNATURES.level1SignatureHex);
  });

  it('deduplicates rescans of the same barcode', () => {
    const collector = new SignatureCollector();
    const first = collector.add(hexToBytes(SOLEA_TICKET_HEX));
    const again = collector.add(hexToBytes(SOLEA_TICKET_HEX));

    if (first.status !== 'added') throw new Error(`unexpected status ${first.status}`);
    if (again.status !== 'duplicate') throw new Error(`unexpected status ${again.status}`);
    expect(again.group).toBe(first.group);
    expect(first.group.tickets).toHaveLength(1);
    expect(collector.size).toBe(1);
  });

  it('reports the live group on each add', () => {
    const collector = new SignatureCollector();
    const first = collector.add(hexToBytes(SOLEA_TICKET_HEX));
    const second = collector.add(hexToBytes(CTS_TICKET_HEX));

    if (first.status !== 'added' || second.status !== 'added') throw new Error('unexpected status');
    expect(second.group).toBe(first.group);
    expect(first.group.tickets).toHaveLength(2);
  });

  it('reports an unreadable scan as invalid without throwing', () => {
    const collector = new SignatureCollector();
    const result = collector.add(new Uint8Array([1, 2, 3]));

    expect(result.status).toBe('invalid');
    if (result.status === 'invalid') expect(result.error).toBeInstanceOf(Error);
    expect(collector.size).toBe(0);
    expect(collector.groups()).toHaveLength(0);
  });

  it('looks a group up by key or by id label', () => {
    const collector = new SignatureCollector();
    collector.add(hexToBytes(SOLEA_TICKET_HEX));
    collector.add(hexToBytes(CAR_JAUNE_TICKET_HEX));

    expect(collector.group('3703/7')?.key.securityProviderNum).toBe(3703);
    expect(collector.group(signatureKey({ securityProviderIA5: 'IWN8', keyId: 1 }))?.key.id).toBe('IWN8/1');
    expect(collector.group('9999/9')).toBeUndefined();
  });
});

describe('collectSignatures', () => {
  it('classifies a batch in one call', () => {
    const groups = collectSignatures(ALL_TICKETS_HEX.map(hexToBytes));
    expect(groups.map(g => [g.key.id, g.tickets.length])).toEqual([
      ['1187/0', 1],
      ['3703/1', 1],
      ['3703/2', 1],
      ['3703/7', 2],
      ['5152/3', 3],
      ['IWN8/1', 1],
    ]);
  });

  it('names the failing payload index', () => {
    const payloads = [hexToBytes(SOLEA_TICKET_HEX), new Uint8Array([0xff])];
    expect(() => collectSignatures(payloads)).toThrow(/Payload #1/);
  });
});
