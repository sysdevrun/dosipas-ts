import { parseKeysXml, findKeyInXml, getPublicKey as derivePublicKey } from 'dosipas-ts';
import type { Level1KeyProvider, UicPublicKeyEntry } from 'dosipas-ts';

let cachedXml: string | null = null;
let cachedKeys: UicPublicKeyEntry[] | null = null;

/** NIST FIPS 186-4 ECDSA P-256 test vector private key (Level 1). */
const FIPS_L1_PRIV_HEX = 'c9806898a0334916c860748880a541f093b579a9b1f32934d86c363c39800357';

/** sysdevrun-dosipas P-256 public key (DER SPKI) for RICS 9950, key id 1. */
const SYSDEVRUN_PUB_HEX =
  '3059301306072a8648ce3d020106082a8648ce3d030107034200040271ce4245f7c34943f8c695398e5483ce6c9e486a6d61f6ee282d86bf407987111b7e45eb841032ed1ffb750ae7d0ebb55591c9eb47ea74047035bf0363f1c5';

let cachedFipsL1PubKey: Uint8Array | null = null;
let cachedSysdevrunPubKey: Uint8Array | null = null;

function getFipsL1PublicKey(): Uint8Array {
  if (!cachedFipsL1PubKey) {
    const privBytes = new Uint8Array(FIPS_L1_PRIV_HEX.match(/.{1,2}/g)!.map((b) => parseInt(b, 16)));
    cachedFipsL1PubKey = derivePublicKey(privBytes, 'P-256');
  }
  return cachedFipsL1PubKey;
}

function getSysdevrunPublicKey(): Uint8Array {
  if (!cachedSysdevrunPubKey) {
    cachedSysdevrunPubKey = new Uint8Array(
      SYSDEVRUN_PUB_HEX.match(/.{1,2}/g)!.map((b) => parseInt(b, 16)),
    );
  }
  return cachedSysdevrunPubKey;
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

export async function createKeyProvider(
  trustFipsKey = false,
  trustSysdevrunKey = false,
): Promise<Level1KeyProvider> {
  const xml = await loadKeysXml();
  return {
    async getPublicKey(securityProvider, keyId) {
      const issuerCode = securityProvider.num ?? 0;
      if (trustFipsKey && issuerCode === 9999 && keyId === 0) {
        return getFipsL1PublicKey();
      }
      if (trustSysdevrunKey && issuerCode === 9950 && keyId === 1) {
        return getSysdevrunPublicKey();
      }
      const key = findKeyInXml(xml, issuerCode, keyId);
      if (!key) {
        throw new Error(`Key not found: issuer=${issuerCode}, keyId=${keyId}`);
      }
      return key;
    },
  };
}
