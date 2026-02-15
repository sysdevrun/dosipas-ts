import { parseKeysXml, findKeyInXml, getPublicKey as derivePublicKey } from 'dosipas-ts';
import type { Level1KeyProvider, UicPublicKeyEntry } from 'dosipas-ts';

let cachedXml: string | null = null;
let cachedKeys: UicPublicKeyEntry[] | null = null;

/** NIST FIPS 186-4 ECDSA P-256 test vector private key (Level 1). */
const FIPS_L1_PRIV_HEX = 'c9806898a0334916c860748880a541f093b579a9b1f32934d86c363c39800357';

let cachedFipsL1PubKey: Uint8Array | null = null;

function getFipsL1PublicKey(): Uint8Array {
  if (!cachedFipsL1PubKey) {
    const privBytes = new Uint8Array(FIPS_L1_PRIV_HEX.match(/.{1,2}/g)!.map((b) => parseInt(b, 16)));
    cachedFipsL1PubKey = derivePublicKey(privBytes, 'P-256');
  }
  return cachedFipsL1PubKey;
}

export async function loadKeysXml(): Promise<string> {
  if (cachedXml) return cachedXml;
  const resp = await fetch('./uic-publickeys.xml');
  if (!resp.ok) throw new Error(`Failed to load public keys: ${resp.status}`);
  cachedXml = await resp.text();
  return cachedXml;
}

export async function getKeys(): Promise<UicPublicKeyEntry[]> {
  if (cachedKeys) return cachedKeys;
  const xml = await loadKeysXml();
  cachedKeys = parseKeysXml(xml);
  return cachedKeys;
}

export async function createKeyProvider(trustFipsKey = false): Promise<Level1KeyProvider> {
  const xml = await loadKeysXml();
  return {
    async getPublicKey(securityProvider, keyId) {
      const issuerCode = securityProvider.num ?? 0;
      if (trustFipsKey && issuerCode === 9999 && keyId === 0) {
        return getFipsL1PublicKey();
      }
      const key = findKeyInXml(xml, issuerCode, keyId);
      if (!key) {
        throw new Error(`Key not found: issuer=${issuerCode}, keyId=${keyId}`);
      }
      return key;
    },
  };
}
