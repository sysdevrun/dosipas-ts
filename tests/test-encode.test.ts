import { describe, it, expect } from 'vitest';
import {
  signLevel1,
  signAndEncodeTicket,
  encodeTicketToBytes,
  controlTicket,
  getPublicKey,
  CURVES,
} from '../src/index';
import type { UicBarcodeTicket, Level1KeyProvider } from '../src/index';

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s/g, '');
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

const FIPS_KEY_1 = 'c9806898a0334916c860748880a541f093b579a9b1f32934d86c363c39800357';

/** Minimal FCB3 ticket with no issuingTime (tests encoder defaults it to 0). */
function makeFCB3Ticket(): UicBarcodeTicket {
  return {
    format: 'U2',
    level2SignedData: {
      level1Data: {
        securityProviderNum: 9999,
        keyId: 1,
        dataSequence: [{
          dataFormat: 'FCB3',
          decoded: {
            issuingDetail: {
              issuerNum: 9999,
              issuingYear: 2026,
              issuingDay: 50,
              specimen: true,
              securePaperTicket: false,
              activated: true,
            },
            transportDocument: [
              { ticket: { key: 'openTicket', value: { returnIncluded: false } } },
            ],
          },
        }],
      },
    },
  };
}

describe('encode → sign → control round-trip', () => {
  it('signLevel1 + encodeTicketToBytes + controlTicket verifies L1 signature', async () => {
    const ticket = makeFCB3Ticket();
    ticket.level2SignedData.level1Data.level1KeyAlg = CURVES['P-256'].keyAlgOid;
    ticket.level2SignedData.level1Data.level1SigningAlg = CURVES['P-256'].sigAlgOid;

    const l1Sig = signLevel1(ticket, hexToBytes(FIPS_KEY_1), 'P-256');
    const withSig: UicBarcodeTicket = {
      ...ticket,
      level2SignedData: {
        ...ticket.level2SignedData,
        level1Signature: l1Sig,
      },
    };
    const hex = bytesToHex(encodeTicketToBytes(withSig));

    const pubKey = getPublicKey(hexToBytes(FIPS_KEY_1), 'P-256');
    const provider: Level1KeyProvider = {
      async getPublicKey() { return pubKey; },
    };
    const result = await controlTicket(hex, { level1KeyProvider: provider });
    expect(result.checks.decode.passed).toBe(true);
    expect(result.checks.level1Signature.passed).toBe(true);
  });

  it('signAndEncodeTicket + controlTicket verifies L1 signature', async () => {
    const ticket = makeFCB3Ticket();

    const l1Key = {
      privateKey: hexToBytes(FIPS_KEY_1),
      publicKey: getPublicKey(hexToBytes(FIPS_KEY_1), 'P-256'),
      curve: 'P-256' as const,
    };

    const hex = bytesToHex(signAndEncodeTicket(ticket, l1Key));

    const provider: Level1KeyProvider = {
      async getPublicKey() { return l1Key.publicKey; },
    };
    const result = await controlTicket(hex, { level1KeyProvider: provider });
    expect(result.checks.decode.passed).toBe(true);
    expect(result.checks.level1Signature.passed).toBe(true);
  });
});
