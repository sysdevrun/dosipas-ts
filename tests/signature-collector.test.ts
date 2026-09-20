import { describe, it, expect } from 'vitest';

import {
  SignatureCollector,
  collectSignatures,
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
    for (const hex of ALL_TICKETS_HEX) collector.add(hexToBytes(hex));

    const groups = collector.groups();
    expect(groups.map(g => g.id)).toEqual([
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

  it('exposes the key identity fields on each group', () => {
    const collector = new SignatureCollector();
    collector.add(hexToBytes(SOLEA_TICKET_HEX));
    collector.add(hexToBytes(CAR_JAUNE_TICKET_HEX));

    const [solea, carJaune] = collector.groups();
    expect(solea.securityProviderNum).toBe(3703);
    expect(solea.securityProviderIA5).toBeUndefined();
    expect(solea.keyId).toBe(7);
    expect(carJaune.securityProviderNum).toBeUndefined();
    expect(carJaune.securityProviderIA5).toBe(CAR_JAUNE_SIGNATURES.securityProviderIA5);
    expect(carJaune.keyId).toBe(CAR_JAUNE_SIGNATURES.keyId);
  });

  it('extracts the signatures and Level 1 algorithm OIDs of each ticket', () => {
    const collector = new SignatureCollector();
    const { ticket } = collector.add(hexToBytes(SOLEA_TICKET_HEX));

    expect(bytesToHex(ticket.level1Signature!)).toBe(SOLEA_SIGNATURES.level1SignatureHex);
    // The level 2 signature is a DER SEQUENCE (its exact bytes are not fixtured).
    expect(ticket.level2Signature![0]).toBe(0x30);
    expect(ticket.level1KeyAlg).toBe(SOLEA_SIGNATURES.level1KeyAlg);
    expect(ticket.level1SigningAlg).toBe(SOLEA_SIGNATURES.level1SigningAlg);
  });

  it('leaves level2Signature undefined for static barcodes', () => {
    const collector = new SignatureCollector();
    const { ticket } = collector.add(hexToBytes(CAR_JAUNE_TICKET_HEX));
    expect(ticket.level2Signature).toBeUndefined();
    expect(bytesToHex(ticket.level1Signature!)).toBe(CAR_JAUNE_SIGNATURES.level1SignatureHex);
  });

  it('deduplicates rescans of the same barcode', () => {
    const collector = new SignatureCollector();
    const first = collector.add(hexToBytes(SOLEA_TICKET_HEX));
    const again = collector.add(hexToBytes(SOLEA_TICKET_HEX));

    expect(first.duplicate).toBe(false);
    expect(again.duplicate).toBe(true);
    expect(again.group).toBe(first.group);
    expect(first.group.tickets).toHaveLength(1);
    expect(collector.size).toBe(1);
  });

  it('reports the live group on each add', () => {
    const collector = new SignatureCollector();
    const first = collector.add(hexToBytes(SOLEA_TICKET_HEX));
    const second = collector.add(hexToBytes(CTS_TICKET_HEX));

    expect(second.group).toBe(first.group);
    expect(first.group.tickets).toHaveLength(2);
  });

  it('throws on a payload that is not a UIC barcode', () => {
    const collector = new SignatureCollector();
    expect(() => collector.add(new Uint8Array([1, 2, 3]))).toThrow();
    expect(collector.size).toBe(0);
  });
});

describe('collectSignatures', () => {
  it('classifies a batch in one call', () => {
    const groups = collectSignatures(ALL_TICKETS_HEX.map(hexToBytes));
    expect(groups.map(g => [g.id, g.tickets.length])).toEqual([
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
