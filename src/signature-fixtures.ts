/**
 * Signature fixture data extracted from real-world ticket barcodes.
 *
 * These fixtures contain the DER-encoded signatures and security metadata
 * for use in signature verification unit tests.
 *
 * Source tickets: intercode6-ts/src/fixtures.ts
 *   - SNCF_TER_TICKET_HEX
 *   - SOLEA_TICKET_HEX
 *   - CTS_TICKET_HEX
 */

// ---------------------------------------------------------------------------
// SNCF TER ticket
// ---------------------------------------------------------------------------

export const SNCF_TER_SIGNATURES = {
  /** Issuer RICS code (securityProviderNum) — used to look up level 1 key. */
  securityProviderNum: 1187,
  /** Key identifier — used with securityProviderNum to find the level 1 key. */
  keyId: 1,
  /** Level 1 key algorithm OID: DSA (no named curve). */
  level1KeyAlg: '2.16.840.1.101.3.4.3.1',
  /** Level 2 key algorithm OID: secp256r1 (P-256). */
  level2KeyAlg: '1.2.840.10045.3.1.7',
  /** Level 1 signing algorithm OID: DSA with SHA-224. */
  level1SigningAlg: '2.16.840.1.101.3.4.3.1',
  /** Level 2 signing algorithm OID: ECDSA with SHA-256. */
  level2SigningAlg: '1.2.840.10045.4.3.2',

  /**
   * Level 1 signature — DER-encoded DSA signature (46 bytes).
   *
   * SEQUENCE {
   *   INTEGER r (20 bytes): 7a71a4d9abdf2204ae40d6dd2dff4adb30df5e44
   *   INTEGER s (20 bytes): 66856f3933964f825f1c825da94a5e3868ffe649
   * }
   */
  level1SignatureHex:
    '302c02147a71a4d9abdf2204ae40d6dd2dff4adb30df5e44' +
    '021466856f3933964f825f1c825da94a5e3868ffe649',

  /**
   * Level 2 signature — DER-encoded ECDSA P-256 signature (70 bytes).
   *
   * SEQUENCE {
   *   INTEGER r (32 bytes): 24df3d92d8f23d0b01572732e3752ce179f65a8160128341b86f9772f6677a14
   *   INTEGER s (32 bytes): 149d2950f3925fea703f4048eb3ada17649cdd2228ab5319cbd9c0d59d5cf603
   * }
   */
  level2SignatureHex:
    '3044022024df3d92d8f23d0b01572732e3752ce179f65a81' +
    '60128341b86f9772f6677a140220149d2950f3925fea703f' +
    '4048eb3ada17649cdd2228ab5319cbd9c0d59d5cf603',
} as const;

// ---------------------------------------------------------------------------
// Soléa ticket
// ---------------------------------------------------------------------------

export const SOLEA_SIGNATURES = {
  /** Issuer RICS code (securityProviderNum) — used to look up level 1 key. */
  securityProviderNum: 1187,
  /** Key identifier — used with securityProviderNum to find the level 1 key. */
  keyId: 1,
  /** Level 1 key algorithm OID: secp256r1 (P-256). */
  level1KeyAlg: '1.2.840.10045.3.1.7',
  /** Level 2 key algorithm OID: secp256r1 (P-256). */
  level2KeyAlg: '1.2.840.10045.3.1.7',
  /** Level 1 signing algorithm OID: ECDSA with SHA-256. */
  level1SigningAlg: '1.2.840.10045.4.3.2',
  /** Level 2 signing algorithm OID: ECDSA with SHA-256. */
  level2SigningAlg: '1.2.840.10045.4.3.2',

  /**
   * Level 1 signature — DER-encoded ECDSA P-256 signature (71 bytes).
   *
   * SEQUENCE {
   *   INTEGER r (33 bytes, 0x00-padded): 00c02fa08b4a288401a053dd250c1f748ae51d16b9aac26eacc09056695f0abe68
   *   INTEGER s (32 bytes):              50c1f1b13a5e8e126441f84159e5b3188d505e73354492b8de369441daa7285b
   * }
   */
  level1SignatureHex:
    '30450221' +
    '00c02fa08b4a288401a053dd250c1f748ae51d16b9aac26e' +
    'acc09056695f0abe68' +
    '0220' +
    '50c1f1b13a5e8e126441f84159e5b3188d505e73354492b8' +
    'de369441daa7285b',

  /**
   * Level 2 signature — DER-encoded ECDSA P-256 signature (71 bytes).
   *
   * SEQUENCE {
   *   INTEGER r (32 bytes):              2a79f008376051f020eae108d0e9950314cac19c4c580249be4b530ec2250ccb
   *   INTEGER s (33 bytes, 0x00-padded): 00a00d805f051efcd130b17b76bf10969b626ed026423f6024d34446eae9168fa3
   * }
   */
  level2SignatureHex:
    '30450220' +
    '2a79f008376051f020eae108d0e9950314cac19c4c580249' +
    'be4b530ec2250ccb' +
    '0221' +
    '00a00d805f051efcd130b17b76bf10969b626ed026423f60' +
    '24d34446eae9168fa3',
} as const;

// ---------------------------------------------------------------------------
// CTS ticket
// ---------------------------------------------------------------------------

export const CTS_SIGNATURES = {
  /** Issuer RICS code (securityProviderNum) — used to look up level 1 key. */
  securityProviderNum: 1187,
  /** Key identifier — used with securityProviderNum to find the level 1 key. */
  keyId: 1,
  /** Level 1 key algorithm OID: secp256r1 (P-256). */
  level1KeyAlg: '1.2.840.10045.3.1.7',
  /** Level 2 key algorithm OID: secp256r1 (P-256). */
  level2KeyAlg: '1.2.840.10045.3.1.7',
  /** Level 1 signing algorithm OID: ECDSA with SHA-256. */
  level1SigningAlg: '1.2.840.10045.4.3.2',
  /** Level 2 signing algorithm OID: ECDSA with SHA-256. */
  level2SigningAlg: '1.2.840.10045.4.3.2',

  /**
   * Level 1 signature — DER-encoded ECDSA P-256 signature (72 bytes).
   *
   * SEQUENCE {
   *   INTEGER r (33 bytes, 0x00-padded): 008974af39d91452785b211f49ec2e36302b2b73ec3b99f5cdba5f1bf5c9e7cb72
   *   INTEGER s (33 bytes, 0x00-padded): 00f468337ab677c729a43b601c8df31f0c9c9923be5711ace720943c1f99b2a34b
   * }
   */
  level1SignatureHex:
    '30460221' +
    '008974af39d91452785b211f49ec2e36302b2b73ec3b99f5' +
    'cdba5f1bf5c9e7cb72' +
    '0221' +
    '00f468337ab677c729a43b601c8df31f0c9c9923be5711ac' +
    'e720943c1f99b2a34b',

  /**
   * Level 2 signature — DER-encoded ECDSA P-256 signature (71 bytes).
   *
   * SEQUENCE {
   *   INTEGER r (32 bytes):              2a79f008376051f020eae108d0e9950314cac19c4c580249be4b530ec2250ccb
   *   INTEGER s (33 bytes, 0x00-padded): 00a00d805f051efcd130b17b76bf10969b626ed026423f6024d34446eae9168fa3
   * }
   *
   * Note: identical to Soléa level2Signature (same level 2 key pair).
   */
  level2SignatureHex:
    '30450220' +
    '2a79f008376051f020eae108d0e9950314cac19c4c580249' +
    'be4b530ec2250ccb' +
    '0221' +
    '00a00d805f051efcd130b17b76bf10969b626ed026423f60' +
    '24d34446eae9168fa3',
} as const;
