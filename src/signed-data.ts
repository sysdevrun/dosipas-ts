/**
 * Signed data extraction for UIC barcode signature verification.
 *
 * Uses `decodeWithMetadata` to extract the exact original bytes that were
 * signed, avoiding any re-encoding that could introduce mismatches.
 *
 * `extractTicket` produces the canonical {@link ExtractedTicket} record that
 * the rest of the library consumes: the verifier, the key-recovery API and
 * the signature collector all accept it in place of raw payload bytes, so a
 * scan pipeline decodes each payload exactly once.
 */
import {
  SchemaCodec,
  SchemaBuilder,
  BitBuffer,
  type SchemaNode,
  type DecodedNode,
} from 'asn1-per-ts';
import { HEADER_SCHEMAS } from './schemas.js';

// ---------------------------------------------------------------------------
// Codec cache (separate from decoder/encoder to avoid coupling)
// ---------------------------------------------------------------------------

const headerCodecCache = new Map<number, SchemaCodec>();

function getHeaderCodec(version: number): SchemaCodec {
  let codec = headerCodecCache.get(version);
  if (codec) return codec;
  const schemas = HEADER_SCHEMAS[version];
  if (!schemas) {
    throw new Error(`No schema for header v${version}. Supported: v1, v2`);
  }
  codec = new SchemaCodec(schemas.UicBarcodeHeader as SchemaNode);
  headerCodecCache.set(version, codec);
  return codec;
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Identity of a Level 1 signing key: issuer + keyId.
 *
 * This is the classification key for collected signatures, the lookup key
 * for `Level1KeyProvider`, and what `findKeyInXml` accepts.
 */
export interface SignatureKey {
  /** Issuer RICS code, when the barcode identifies its issuer numerically. */
  securityProviderNum?: number;
  /** Issuer IA5 string, when the barcode identifies its issuer as text. */
  securityProviderIA5?: string;
  /** Key identifier within the issuer's key set. */
  keyId?: number;
  /**
   * Canonical label: `"<issuer>/<keyId>"`, where issuer is the RICS code or
   * the IA5 string (`"1187/1"`, `"IWN8/1"`); a missing part reads `"?"`.
   * A purely numeric IA5 issuer could spell the same label as a RICS code,
   * so grouping and equality use the three fields above, not this string.
   */
  id: string;
}

/** Build a {@link SignatureKey}, computing its canonical `id`. */
export function signatureKey(
  fields: Omit<SignatureKey, 'id'>,
): SignatureKey {
  const { securityProviderNum, securityProviderIA5, keyId } = fields;
  return {
    securityProviderNum,
    securityProviderIA5,
    keyId,
    id: `${securityProviderNum ?? securityProviderIA5 ?? '?'}/${keyId ?? '?'}`,
  };
}

/** One level's signed bytes, signature and algorithm OIDs. */
export interface LevelSignatureData {
  /** The exact original bytes covered by this level's signature. */
  signedBytes: Uint8Array;
  /** This level's signature (DER), absent when the barcode carries none. */
  signature?: Uint8Array;
  /** Key algorithm OID, when the barcode carries one. */
  keyAlg?: string;
  /** Signing algorithm OID, when the barcode carries one. */
  signingAlg?: string;
}

/**
 * Everything extractable from one barcode payload, structured per level.
 *
 * The canonical record consumed across the library: `verifySignatures`,
 * `verifyLevel1Signature`, `verifyLevel2Signature`, `recoverLevel1PublicKey`
 * and `SignatureCollector.add` all accept it in place of raw payload bytes.
 */
export interface ExtractedTicket {
  /** Raw barcode payload bytes, exactly as scanned. */
  bytes: Uint8Array;
  /** Level 1 key identity (issuer + keyId). */
  key: SignatureKey;
  /** Level 1: signed bytes, signature and algorithm OIDs. */
  level1: LevelSignatureData;
  /** Level 2, plus its embedded public key. Static barcodes carry no signature. */
  level2: LevelSignatureData & {
    /** The Level 2 public key embedded in `level1Data`, when present. */
    publicKey?: Uint8Array;
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Extract the signed data bytes, signatures and key identity from a UIC
 * barcode.
 *
 * This decodes the barcode header with metadata tracking, then reads the
 * exact original bytes from the source buffer via `rawBytes`. No re-encoding
 * is performed.
 *
 * @param bytes - The raw barcode payload bytes.
 * @returns The canonical extracted ticket record.
 * @throws When the payload is not a decodable UIC barcode.
 */
export function extractTicket(bytes: Uint8Array): ExtractedTicket {
  // Peek the header version
  const peekBuf = BitBuffer.from(bytes);
  peekBuf.readBit(); // skip optional bitmap
  const format = SchemaBuilder.build({ type: 'IA5String' } as SchemaNode).decode(peekBuf) as string;

  const headerVersionMatch = format.match(/^U(\d+)$/);
  if (!headerVersionMatch) {
    throw new Error(`Unknown header format "${format}"`);
  }
  const headerVersion = parseInt(headerVersionMatch[1], 10);

  // Decode with metadata to get exact byte positions
  const codec = getHeaderCodec(headerVersion);
  const root: DecodedNode = codec.decodeWithMetadata(bytes);

  // Navigate the metadata tree
  const headerFields = root.value as Record<string, DecodedNode>;

  // level2SignedData node — its rawBytes are what level2Signature signs
  const level2SignedDataNode = headerFields.level2SignedData;
  const level2SignedBytes = level2SignedDataNode.meta.rawBytes;

  // level1Data node — its rawBytes are what level1Signature signs
  const l2Fields = level2SignedDataNode.value as Record<string, DecodedNode>;
  const level1DataNode = l2Fields.level1Data;
  const level1DataBytes = level1DataNode.meta.rawBytes;

  // Extract security metadata by stripping metadata from the relevant nodes
  const l1Fields = level1DataNode.value as Record<string, DecodedNode>;

  return {
    bytes,
    key: signatureKey({
      securityProviderNum: getNodeValue(l1Fields.securityProviderNum) as number | undefined,
      securityProviderIA5: getNodeValue(l1Fields.securityProviderIA5) as string | undefined,
      keyId: getNodeValue(l1Fields.keyId) as number | undefined,
    }),
    level1: {
      signedBytes: level1DataBytes,
      signature: getNodeValue(l2Fields.level1Signature) as Uint8Array | undefined,
      keyAlg: getNodeValue(l1Fields.level1KeyAlg) as string | undefined,
      signingAlg: getNodeValue(l1Fields.level1SigningAlg) as string | undefined,
    },
    level2: {
      signedBytes: level2SignedBytes,
      signature: getNodeValue(headerFields.level2Signature) as Uint8Array | undefined,
      keyAlg: getNodeValue(l1Fields.level2KeyAlg) as string | undefined,
      signingAlg: getNodeValue(l1Fields.level2SigningAlg) as string | undefined,
      publicKey: getNodeValue(l1Fields.level2PublicKey) as Uint8Array | undefined,
    },
  };
}

/**
 * Resolve a payload-or-ticket input to an {@link ExtractedTicket}, extracting
 * only when given raw bytes. Shared by the APIs that accept either form.
 */
export function toExtractedTicket(input: Uint8Array | ExtractedTicket): ExtractedTicket {
  return input instanceof Uint8Array ? extractTicket(input) : input;
}

/**
 * Get the plain value from a DecodedNode, handling optional/absent fields.
 */
function getNodeValue(node: DecodedNode | undefined): unknown {
  if (!node) return undefined;
  if (node.meta.optional && !node.meta.present && !node.meta.isDefault) {
    return undefined;
  }
  return node.value;
}
