/**
 * Encoder for UIC barcode tickets with Intercode 6 extensions.
 *
 * Encodes a {@link UicBarcodeTicketInput} object into a hex string suitable
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
  UicBarcodeTicketInput,
  Level1DataInput,
  Level2SignedDataInput,
  UicBarcodeInput,
  IssuingDetailInput,
  IntercodeIssuingDataInput,
  IntercodeDynamicDataInput,
  UicDynamicContentDataInput,
  TransportDocumentInput,
} from './types';

// ---------------------------------------------------------------------------
// Codec caches (separate from decoder to avoid coupling)
// ---------------------------------------------------------------------------

const headerCodecCache = new Map<number, SchemaCodec>();
const level1DataCodecCache = new Map<number, SchemaCodec>();
const level2DataCodecCache = new Map<number, SchemaCodec>();
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

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Encode a UIC barcode ticket to a hex string.
 *
 * @param input - The ticket data to encode.
 * @returns Hex string of the encoded barcode payload.
 */
export function encodeTicket(input: UicBarcodeTicketInput): string {
  const headerVersion = input.headerVersion ?? 2;
  const fcbVersion = input.fcbVersion ?? 2;

  // Step 1: Encode the rail ticket data
  const railTicketBytes = encodeRailTicket(fcbVersion, input);

  // Step 2: Build the data sequence
  const dataSequence: Array<{ dataFormat: string; data: Uint8Array }> = [
    { dataFormat: `FCB${fcbVersion}`, data: railTicketBytes },
  ];

  // Step 3: Build Level 2 data (Intercode dynamic or FDC1)
  let level2Data: { dataFormat: string; data: Uint8Array } | undefined;
  if (input.dynamicContentData) {
    level2Data = encodeLevel2Data(input.dynamicContentData);
  } else if (input.dynamicData) {
    level2Data = encodeLevel2Data(input.dynamicData);
  }

  // Step 4: Build the full header structure
  const headerData: Record<string, unknown> = {
    format: `U${headerVersion}`,
    level2SignedData: {
      level1Data: {
        securityProviderNum: input.securityProviderNum,
        keyId: input.keyId,
        dataSequence,
        level1KeyAlg: input.level1KeyAlg,
        level2KeyAlg: input.level2KeyAlg,
        level1SigningAlg: input.level1SigningAlg,
        level2SigningAlg: input.level2SigningAlg,
        level2PublicKey: input.level2PublicKey,
        endOfValidityYear: input.endOfValidityYear,
        endOfValidityDay: input.endOfValidityDay,
        endOfValidityTime: input.endOfValidityTime,
        validityDuration: input.validityDuration,
      },
      level1Signature: input.level1Signature,
      level2Data,
    },
    level2Signature: input.level2Signature,
  };

  // Step 5: Encode the header
  const codec = getHeaderCodec(headerVersion);
  return codec.encodeToHex(headerData);
}

/**
 * Encode a UIC barcode ticket to bytes.
 *
 * @param input - The ticket data to encode.
 * @returns Uint8Array of the encoded barcode payload.
 */
export function encodeTicketToBytes(input: UicBarcodeTicketInput): Uint8Array {
  const hex = encodeTicket(input);
  return new Uint8Array(hex.match(/.{1,2}/g)!.map(b => parseInt(b, 16)));
}

// ---------------------------------------------------------------------------
// Composable encoding primitives
// ---------------------------------------------------------------------------

/**
 * Encode a Level 2 data block (FDC1 or Intercode dynamic data).
 *
 * Uses a type discriminant (`'rics' in input`) to distinguish Intercode
 * dynamic data from UIC FDC1 dynamic content data.
 *
 * @param input - FDC1 or Intercode dynamic data to encode.
 * @returns Object with `dataFormat` string and encoded `data` bytes.
 */
export function encodeLevel2Data(
  input: UicDynamicContentDataInput | IntercodeDynamicDataInput,
): { dataFormat: string; data: Uint8Array } {
  if ('rics' in input) {
    // Intercode dynamic data
    const dynamicBytes = getIntercodeDynamicCodec().encode({
      dynamicContentDay: input.dynamicContentDay ?? 0,
      dynamicContentTime: input.dynamicContentTime,
      dynamicContentUTCOffset: input.dynamicContentUTCOffset,
      dynamicContentDuration: input.dynamicContentDuration,
    });
    return {
      dataFormat: `_${input.rics}.ID1`,
      data: dynamicBytes,
    };
  } else {
    // FDC1 dynamic content data
    const fdc1Bytes = getFdc1Codec().encode(input);
    return { dataFormat: 'FDC1', data: fdc1Bytes };
  }
}

/**
 * Encode the `level1Data` SEQUENCE in isolation.
 *
 * Returns a {@link RawBytes} with the exact PER-encoded bits. The `.data`
 * property gives the `Uint8Array` suitable for signing; the `RawBytes` itself
 * is passed to {@link encodeLevel2SignedData} for bit-precise embedding.
 */
export function encodeLevel1Data(input: Level1DataInput): RawBytes {
  const headerVersion = input.headerVersion ?? 2;
  const fcbVersion = input.fcbVersion ?? 2;

  const railTicketBytes = encodeRailTicket(fcbVersion, input);
  const dataSequence: Array<{ dataFormat: string; data: Uint8Array }> = [
    { dataFormat: `FCB${fcbVersion}`, data: railTicketBytes },
  ];

  const level1Data: Record<string, unknown> = {
    securityProviderNum: input.securityProviderNum,
    keyId: input.keyId,
    dataSequence,
    level1KeyAlg: input.level1KeyAlg,
    level2KeyAlg: input.level2KeyAlg,
    level1SigningAlg: input.level1SigningAlg,
    level2SigningAlg: input.level2SigningAlg,
    level2PublicKey: input.level2PublicKey,
    endOfValidityYear: input.endOfValidityYear,
    endOfValidityDay: input.endOfValidityDay,
    endOfValidityTime: input.endOfValidityTime,
    validityDuration: input.validityDuration,
  };

  const codec = getLevel1DataCodec(headerVersion);
  return codec.encodeToRawBytes(level1Data);
}

/**
 * Encode the `level2SignedData` SEQUENCE.
 *
 * Embeds pre-encoded `level1Data` bytes verbatim via {@link RawBytes}
 * passthrough. Returns a `RawBytes` for signing and embedding into
 * {@link encodeUicBarcode}.
 */
export function encodeLevel2SignedData(input: Level2SignedDataInput): RawBytes {
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
export function encodeUicBarcode(input: UicBarcodeInput): Uint8Array {
  const headerVersionMatch = input.format.match(/^U(\d+)$/);
  if (!headerVersionMatch) {
    throw new Error(`Invalid format "${input.format}", expected "U1" or "U2"`);
  }
  const headerVersion = parseInt(headerVersionMatch[1], 10);

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

function encodeRailTicket(fcbVersion: number, input: Pick<UicBarcodeTicketInput, 'securityProviderNum' | 'railTicket'>): Uint8Array {
  const iss = input.railTicket.issuingDetail;

  // Build extension if intercode issuing data present
  let extension: { extensionId: string; extensionData: Uint8Array } | undefined;
  if (iss.intercodeIssuing) {
    const rics = iss.securityProviderNum ?? input.securityProviderNum ?? 0;
    const issuingBytes = getIntercodeIssuingCodec().encode({
      intercodeVersion: iss.intercodeIssuing.intercodeVersion ?? 1,
      intercodeInstanciation: iss.intercodeIssuing.intercodeInstanciation ?? 1,
      networkId: iss.intercodeIssuing.networkId,
      productRetailer: iss.intercodeIssuing.productRetailer,
    });
    extension = {
      extensionId: iss.intercodeIssuing.extensionId ?? `_${rics}II1`,
      extensionData: issuingBytes,
    };
  }

  // Build the issuing detail
  const issuingDetail: Record<string, unknown> = {
    securityProviderNum: iss.securityProviderNum,
    issuerNum: iss.issuerNum,
    issuingYear: iss.issuingYear,
    issuingDay: iss.issuingDay,
    issuingTime: iss.issuingTime,
    issuerName: iss.issuerName,
    specimen: iss.specimen ?? false,
    securePaperTicket: iss.securePaperTicket ?? false,
    activated: iss.activated ?? true,
    currency: iss.currency,
    currencyFract: iss.currencyFract,
    issuerPNR: iss.issuerPNR,
    extension,
  };

  // Build transport documents
  const transportDocument = input.railTicket.transportDocument?.map((doc) => ({
    ticket: { key: doc.ticketType, value: doc.ticket },
  }));

  // Validate traveler birth-day fields match the target FCB version
  if (input.railTicket.travelerDetail?.traveler) {
    for (const t of input.railTicket.travelerDetail.traveler) {
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

  // Build the full rail ticket data
  const ticketData: Record<string, unknown> = {
    issuingDetail,
    travelerDetail: input.railTicket.travelerDetail,
    transportDocument,
    controlDetail: input.railTicket.controlDetail,
  };

  const codecs = getTicketCodecs(fcbVersion);
  const buf = BitBuffer.alloc();
  codecs.UicRailTicketData.encode(buf, ticketData);
  return buf.toUint8Array();
}
