/**
 * Signed data extraction for UIC barcode signature verification.
 *
 * Uses `decodeWithMetadata` to extract the exact original bytes that were
 * signed, avoiding any re-encoding that could introduce mismatches.
 */
import {
  SchemaCodec,
  SchemaBuilder,
  BitBuffer,
  stripMetadata,
  type SchemaNode,
  type DecodedNode,
} from 'asn1-per-ts';
import type { Codec } from 'asn1-per-ts';
import { HEADER_SCHEMAS } from './schemas';

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

/** Extracted signed data bytes and security metadata from a UIC barcode. */
export interface ExtractedSignedData {
  /** The exact bytes of `level1Data` — signed by level1Signature. */
  level1DataBytes: Uint8Array;
  /** The exact bytes of `level2SignedData` — signed by level2Signature. */
  level2SignedBytes: Uint8Array;

  /** Security metadata extracted from the decoded header. */
  security: {
    securityProviderNum?: number;
    securityProviderIA5?: string;
    keyId?: number;
    level1KeyAlg?: string;
    level2KeyAlg?: string;
    level1SigningAlg?: string;
    level2SigningAlg?: string;
    level2PublicKey?: Uint8Array;
    level1Signature?: Uint8Array;
    level2Signature?: Uint8Array;
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Extract the signed data bytes and security metadata from a UIC barcode.
 *
 * This decodes the barcode header with metadata tracking, then reads the
 * exact original bytes from the source buffer via `rawBytes`. No re-encoding
 * is performed.
 *
 * @param bytes - The raw barcode payload bytes.
 * @returns Extracted signed bytes and security metadata.
 */
export function extractSignedData(bytes: Uint8Array): ExtractedSignedData {
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

  const security: ExtractedSignedData['security'] = {
    securityProviderNum: getNodeValue(l1Fields.securityProviderNum) as number | undefined,
    securityProviderIA5: getNodeValue(l1Fields.securityProviderIA5) as string | undefined,
    keyId: getNodeValue(l1Fields.keyId) as number | undefined,
    level1KeyAlg: getNodeValue(l1Fields.level1KeyAlg) as string | undefined,
    level2KeyAlg: getNodeValue(l1Fields.level2KeyAlg) as string | undefined,
    level1SigningAlg: getNodeValue(l1Fields.level1SigningAlg) as string | undefined,
    level2SigningAlg: getNodeValue(l1Fields.level2SigningAlg) as string | undefined,
    level2PublicKey: getNodeValue(l1Fields.level2PublicKey) as Uint8Array | undefined,
    level1Signature: getNodeValue(l2Fields.level1Signature) as Uint8Array | undefined,
    level2Signature: getNodeValue(headerFields.level2Signature) as Uint8Array | undefined,
  };

  return { level1DataBytes, level2SignedBytes, security };
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
