import { parseKeysXml, findKeyInXml } from 'dosipas-ts';
import type { Level1KeyProvider, UicPublicKeyEntry } from 'dosipas-ts';

let cachedXml: string | null = null;
let cachedKeys: UicPublicKeyEntry[] | null = null;

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

export async function createKeyProvider(): Promise<Level1KeyProvider> {
  const xml = await loadKeysXml();
  return {
    async getPublicKey(securityProvider, keyId) {
      const issuerCode = securityProvider.num ?? 0;
      const key = findKeyInXml(xml, issuerCode, keyId);
      if (!key) {
        throw new Error(`Key not found: issuer=${issuerCode}, keyId=${keyId}`);
      }
      return key;
    },
  };
}
