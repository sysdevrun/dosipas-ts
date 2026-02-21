/**
 * Encoder for UIC barcode tickets with Intercode 6 extensions.
 *
 * Encodes a {@link UicBarcodeTicket} object into a hex string suitable
 * for embedding in an Aztec barcode.
 */
import {
  SchemaCodec,
  SchemaBuilder,
  BitBuffer,
  type SchemaNode,
} from 'asn1-per-ts';
import type { Codec, RawBytes } from 'asn1-per-ts';
import { HEADER_SCHEMAS, RAIL_TICKET_SCHEMAS, INTERCODE_SCHEMAS, DYNAMIC_CONTENT_SCHEMAS } from './schemas';
import type {
  UicBarcodeTicket,
  Level1Data,
  Level2Data,
  UicRailTicketData,
  UicDynamicContentData,
  IntercodeDynamicData,
} from './types';

// ---------------------------------------------------------------------------
// Codec caches (separate from decoder to avoid coupling)
// ---------------------------------------------------------------------------

const headerCodecCache = new Map<number, SchemaCodec>();
const level1DataCodecCache = new Map<number, SchemaCodec>();
const level2DataCodecCache = new Map<number, SchemaCodec>();
const level2ContentCodecCache = new Map<number, SchemaCodec>();
const ticketCodecCache = new Map<number, Record<string, Codec<unknown>>>();
let intercodeIssuingCodec: SchemaCodec | undefined;
let intercodeDynamicCodec: SchemaCodec | undefined;
let fdc1Codec: SchemaCodec | undefined;

function getHeaderCodec(version: number): SchemaCodec {
  let codec = headerCodecCache.get(version);
  if (codec) return codec;
  const schemas = HEADER_SCHEMAS[version];
  if (!schemas) throw new Error(`No schema for header v${version}`);
  codec = new SchemaCodec(schemas.UicBarcodeHeader as SchemaNode);
  headerCodecCache.set(version, codec);
  return codec;
}

function getLevel1DataCodec(version: number): SchemaCodec {
  let codec = level1DataCodecCache.get(version);
  if (codec) return codec;
  const schemas = HEADER_SCHEMAS[version];
  if (!schemas) throw new Error(`No schema for header v${version}`);
  codec = new SchemaCodec(schemas.Level1DataType as SchemaNode);
  level1DataCodecCache.set(version, codec);
  return codec;
}

function getLevel2DataCodec(version: number): SchemaCodec {
  let codec = level2DataCodecCache.get(version);
  if (codec) return codec;
  const schemas = HEADER_SCHEMAS[version];
  if (!schemas) throw new Error(`No schema for header v${version}`);
  codec = new SchemaCodec(schemas.Level2DataType as SchemaNode);
  level2DataCodecCache.set(version, codec);
  return codec;
}

function getLevel2ContentCodec(version: number): SchemaCodec {
  let codec = level2ContentCodecCache.get(version);
  if (codec) return codec;
  const schemas = HEADER_SCHEMAS[version];
  if (!schemas) throw new Error(`No schema for header v${version}`);
  const l2Type = schemas.Level2DataType as any;
  const l2ContentField = l2Type.fields.find((f: any) => f.name === 'level2Data');
  codec = new SchemaCodec(l2ContentField.schema as SchemaNode);
  level2ContentCodecCache.set(version, codec);
  return codec;
}

function getTicketCodecs(version: number): Record<string, Codec<unknown>> {
  let codecs = ticketCodecCache.get(version);
  if (codecs) return codecs;
  const schemas = RAIL_TICKET_SCHEMAS[version];
  if (!schemas) throw new Error(`No schema for FCB${version}`);
  codecs = SchemaBuilder.buildAll(schemas as Record<string, SchemaNode>);
  ticketCodecCache.set(version, codecs);
  return codecs;
}

function getIntercodeIssuingCodec(): SchemaCodec {
  if (intercodeIssuingCodec) return intercodeIssuingCodec;
  intercodeIssuingCodec = new SchemaCodec(INTERCODE_SCHEMAS.IntercodeIssuingData as SchemaNode);
  intercodeDynamicCodec = new SchemaCodec(INTERCODE_SCHEMAS.IntercodeDynamicData as SchemaNode);
  return intercodeIssuingCodec;
}

function getIntercodeDynamicCodec(): SchemaCodec {
  if (intercodeDynamicCodec) return intercodeDynamicCodec;
  getIntercodeIssuingCodec();
  return intercodeDynamicCodec!;
}

function getFdc1Codec(): SchemaCodec {
  if (fdc1Codec) return fdc1Codec;
  fdc1Codec = new SchemaCodec(DYNAMIC_CONTENT_SCHEMAS.UicDynamicContentData as SchemaNode);
  return fdc1Codec;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function parseHeaderVersion(format: string): number {
  const match = format.match(/^U(\d+)$/);
  if (!match) throw new Error(`Invalid format "${format}", expected "U1" or "U2"`);
  return parseInt(match[1], 10);
}

function parseFcbVersion(dataFormat: string): number {
  const match = dataFormat.match(/^FCB(\d+)$/);
  if (!match) throw new Error(`Unsupported dataFormat "${dataFormat}"`);
  return parseInt(match[1], 10);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Encode a UIC barcode ticket to a hex string.
 *
 * @param ticket - The decoded ticket structure to encode.
 * @returns Hex string of the encoded barcode payload.
 */
export function encodeTicket(ticket: UicBarcodeTicket): string {
  const headerVersion = parseHeaderVersion(ticket.format);
  const l1 = ticket.level2SignedData.level1Data;

  // Encode each data sequence entry
  const dataSequence = l1.dataSequence.map(entry => {
    if (entry.data) return { dataFormat: entry.dataFormat, data: entry.data };
    if (!entry.decoded) throw new Error('DataSequenceEntry must have data or decoded');
    const fcbVersion = parseFcbVersion(entry.dataFormat);
    return {
      dataFormat: entry.dataFormat,
      data: encodeRailTicket(fcbVersion, entry.decoded, l1.securityProviderNum),
    };
  });

  // Encode level2Data if present
  let level2Data: RawBytes | undefined;
  const l2 = ticket.level2SignedData.level2Data;
  if (l2) {
    level2Data = encodeLevel2Data(l2, ticket.format);
  }

  // Build the full header structure
  const headerData: Record<string, unknown> = {
    format: ticket.format,
    level2SignedData: {
      level1Data: {
        securityProviderNum: l1.securityProviderNum,
        securityProviderIA5: l1.securityProviderIA5,
        keyId: l1.keyId,
        dataSequence,
        level1KeyAlg: l1.level1KeyAlg,
        level2KeyAlg: l1.level2KeyAlg,
        level1SigningAlg: l1.level1SigningAlg,
        level2SigningAlg: l1.level2SigningAlg,
        level2PublicKey: l1.level2PublicKey,
        endOfValidityYear: l1.endOfValidityYear,
        endOfValidityDay: l1.endOfValidityDay,
        endOfValidityTime: l1.endOfValidityTime,
        validityDuration: l1.validityDuration,
      },
      level1Signature: ticket.level2SignedData.level1Signature,
      level2Data,
    },
    level2Signature: ticket.level2Signature,
  };

  const codec = getHeaderCodec(headerVersion);
  return codec.encodeToHex(headerData);
}

/**
 * Encode a UIC barcode ticket to bytes.
 *
 * @param ticket - The decoded ticket structure to encode.
 * @returns Uint8Array of the encoded barcode payload.
 */
export function encodeTicketToBytes(ticket: UicBarcodeTicket): Uint8Array {
  const hex = encodeTicket(ticket);
  return new Uint8Array(hex.match(/.{1,2}/g)!.map(b => parseInt(b, 16)));
}

// ---------------------------------------------------------------------------
// Composable encoding primitives
// ---------------------------------------------------------------------------

/**
 * Encode a Level 2 data block from a {@link Level2Data} structure.
 *
 * If the `data` field is present, it is used as-is. Otherwise the `decoded`
 * field is PER-encoded based on the `dataFormat`.
 *
 * Returns a {@link RawBytes} with the exact PER-encoded bits. The `.data`
 * property gives the `Uint8Array` suitable for signing; the `RawBytes` itself
 * is passed to {@link encodeLevel2SignedData} for bit-precise embedding.
 *
 * @param l2Data - Level 2 data with either raw `data` or `decoded` content.
 * @param format - Header format string (e.g. "U1" or "U2").
 * @returns RawBytes containing the PER-encoded level2Data SEQUENCE.
 */
export function encodeLevel2Data(
  l2Data: Level2Data,
  format: string,
): RawBytes {
  const headerVersion = parseHeaderVersion(format);
  const data = l2Data.data ?? (() => {
    if (!l2Data.decoded) throw new Error('Level2Data must have data or decoded');
    return encodeLevel2DataDecoded(l2Data.dataFormat, l2Data.decoded);
  })();
  const codec = getLevel2ContentCodec(headerVersion);
  return codec.encodeToRawBytes({ dataFormat: l2Data.dataFormat, data });
}

/**
 * Encode the `level1Data` SEQUENCE in isolation.
 *
 * Returns a {@link RawBytes} with the exact PER-encoded bits. The `.data`
 * property gives the `Uint8Array` suitable for signing; the `RawBytes` itself
 * is passed to {@link encodeLevel2SignedData} for bit-precise embedding.
 *
 * @param level1Data - The Level 1 data to encode.
 * @param format - Header format string (e.g. "U1" or "U2").
 */
export function encodeLevel1Data(level1Data: Level1Data, format: string): RawBytes {
  const headerVersion = parseHeaderVersion(format);

  // Encode each data sequence entry
  const dataSequence = level1Data.dataSequence.map(entry => {
    if (entry.data) return { dataFormat: entry.dataFormat, data: entry.data };
    if (!entry.decoded) throw new Error('DataSequenceEntry must have data or decoded');
    const fcbVersion = parseFcbVersion(entry.dataFormat);
    return {
      dataFormat: entry.dataFormat,
      data: encodeRailTicket(fcbVersion, entry.decoded, level1Data.securityProviderNum),
    };
  });

  const l1Data: Record<string, unknown> = {
    securityProviderNum: level1Data.securityProviderNum,
    securityProviderIA5: level1Data.securityProviderIA5,
    keyId: level1Data.keyId,
    dataSequence,
    level1KeyAlg: level1Data.level1KeyAlg,
    level2KeyAlg: level1Data.level2KeyAlg,
    level1SigningAlg: level1Data.level1SigningAlg,
    level2SigningAlg: level1Data.level2SigningAlg,
    level2PublicKey: level1Data.level2PublicKey,
    endOfValidityYear: level1Data.endOfValidityYear,
    endOfValidityDay: level1Data.endOfValidityDay,
    endOfValidityTime: level1Data.endOfValidityTime,
    validityDuration: level1Data.validityDuration,
  };

  const codec = getLevel1DataCodec(headerVersion);
  return codec.encodeToRawBytes(l1Data);
}

/**
 * Encode the `level2SignedData` SEQUENCE.
 *
 * Embeds pre-encoded `level1Data` bytes verbatim via {@link RawBytes}
 * passthrough. Returns a `RawBytes` for signing and embedding into
 * {@link encodeUicBarcode}.
 */
export function encodeLevel2SignedData(input: {
  headerVersion?: number;
  level1Data: RawBytes;
  level1Signature: Uint8Array;
  level2Data?: RawBytes;
}): RawBytes {
  const headerVersion = input.headerVersion ?? 2;

  const level2SignedData: Record<string, unknown> = {
    level1Data: input.level1Data,
    level1Signature: input.level1Signature,
    level2Data: input.level2Data,
  };

  const codec = getLevel2DataCodec(headerVersion);
  return codec.encodeToRawBytes(level2SignedData);
}

/**
 * Encode the outermost `UicBarcodeHeader` SEQUENCE.
 *
 * Embeds pre-encoded `level2SignedData` bytes verbatim via {@link RawBytes}
 * passthrough. Returns the final barcode payload bytes.
 */
export function encodeUicBarcode(input: {
  format: string;
  level2SignedData: RawBytes;
  level2Signature?: Uint8Array;
}): Uint8Array {
  const headerVersion = parseHeaderVersion(input.format);

  const headerData: Record<string, unknown> = {
    format: input.format,
    level2SignedData: input.level2SignedData,
    level2Signature: input.level2Signature,
  };

  const codec = getHeaderCodec(headerVersion);
  return codec.encode(headerData);
}

// ---------------------------------------------------------------------------
// Internal encoding helpers
// ---------------------------------------------------------------------------

/**
 * Encode the decoded content of a Level 2 data block.
 */
function encodeLevel2DataDecoded(
  dataFormat: string,
  decoded: UicDynamicContentData | IntercodeDynamicData,
): Uint8Array {
  if (dataFormat === 'FDC1') {
    return getFdc1Codec().encode(decoded);
  } else {
    // Intercode dynamic data
    return getIntercodeDynamicCodec().encode(decoded);
  }
}

/**
 * Encode rail ticket data (UicRailTicketData) to PER bytes.
 */
function encodeRailTicket(fcbVersion: number, railTicket: UicRailTicketData, securityProviderNum?: number): Uint8Array {
  const iss = railTicket.issuingDetail;

  let issuingDetail: Record<string, unknown> | undefined;
  if (iss) {
    // Handle extension: re-encode intercode if present, otherwise pass through raw
    const { intercodeIssuing, extension: rawExtension, ...issuingRest } = iss;
    let extension: { extensionId: string; extensionData: Uint8Array } | undefined;
    if (intercodeIssuing) {
      const issuingBytes = getIntercodeIssuingCodec().encode({
        intercodeVersion: intercodeIssuing.intercodeVersion ?? 1,
        intercodeInstanciation: intercodeIssuing.intercodeInstanciation ?? 1,
        networkId: intercodeIssuing.networkId,
        productRetailer: intercodeIssuing.productRetailer,
      });
      extension = {
        extensionId: intercodeIssuing.extensionId ?? `_${iss.securityProviderNum ?? securityProviderNum ?? 0}II1`,
        extensionData: issuingBytes,
      };
    } else {
      extension = rawExtension;
    }

    issuingDetail = { ...issuingRest, extension };

    // FCB3 requires issuingTime as mandatory — default to 0 if not provided
    if (fcbVersion >= 3 && issuingDetail.issuingTime == null) {
      issuingDetail.issuingTime = 0;
    }
  }

  // Validate traveler birth-day fields match the target FCB version
  if (railTicket.travelerDetail?.traveler) {
    for (const t of railTicket.travelerDetail.traveler) {
      if (fcbVersion >= 2 && t.dayOfBirth !== undefined) {
        throw new Error(
          `Traveler field "dayOfBirth" is not valid for FCB v${fcbVersion}. Use "dayOfBirthInMonth" instead.`,
        );
      }
      if (fcbVersion < 2 && t.dayOfBirthInMonth !== undefined) {
        throw new Error(
          `Traveler field "dayOfBirthInMonth" is not valid for FCB v${fcbVersion}. Use "dayOfBirth" instead.`,
        );
      }
    }
  }

  // Transport documents pass through directly (already { ticket: { key, value } } format)
  const ticketData: Record<string, unknown> = {
    issuingDetail,
    travelerDetail: railTicket.travelerDetail,
    transportDocument: railTicket.transportDocument,
    controlDetail: railTicket.controlDetail,
  };

  const codecs = getTicketCodecs(fcbVersion);
  const buf = BitBuffer.alloc();
  codecs.UicRailTicketData.encode(buf, ticketData);
  return buf.toUint8Array();
}
