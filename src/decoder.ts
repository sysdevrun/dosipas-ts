/**
 * Decoder for UIC barcode tickets with Intercode 6 extensions.
 *
 * Decodes a hex-encoded (or binary) UIC barcode payload into a typed
 * {@link UicBarcodeTicket} object. Handles header version detection,
 * FCB rail ticket data dispatch, and Intercode 6 extension decoding.
 */
import {
  SchemaCodec,
  SchemaBuilder,
  BitBuffer,
  type SchemaNode,
} from 'asn1-per-ts';
import type { Codec } from 'asn1-per-ts';
import { HEADER_SCHEMAS, RAIL_TICKET_SCHEMAS, INTERCODE_SCHEMAS, DYNAMIC_CONTENT_SCHEMAS } from './schemas';
import type {
  UicBarcodeTicket,
  RailTicketData,
  IssuingDetail,
  TravelerDetail,
  TransportDocumentEntry,
  ControlDetail,
  IntercodeIssuingData,
  IntercodeDynamicData,
  UicDynamicContentData,
  DataBlock,
  SecurityInfo,
  ExtensionData,
} from './types';

// ---------------------------------------------------------------------------
// Codec caches
// ---------------------------------------------------------------------------

const headerCodecCache = new Map<number, SchemaCodec>();
const ticketCodecCache = new Map<number, Record<string, Codec<unknown>>>();
let intercodeIssuingCodec: SchemaCodec | undefined;
let intercodeDynamicCodec: SchemaCodec | undefined;
let fdc1Codec: SchemaCodec | undefined;

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

function getTicketCodecs(version: number): Record<string, Codec<unknown>> {
  let codecs = ticketCodecCache.get(version);
  if (codecs) return codecs;
  const schemas = RAIL_TICKET_SCHEMAS[version];
  if (!schemas) {
    throw new Error(`No schema for FCB${version}. Supported: FCB1, FCB2, FCB3`);
  }
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
// Pattern helpers
// ---------------------------------------------------------------------------

/**
 * Match Intercode Part 6 issuing extension IDs:
 *   - `_<RICS>II1`   — numeric RICS code prefix (e.g. `_3703II1`)
 *   - `+<CC>II1`     — ISO 3166-1 alpha-2 country code prefix (e.g. `+FRII1`)
 */
function isIntercodeIssuingExtension(extensionId: string): boolean {
  return /^[_+](\d+|[A-Z]{2})II1$/.test(extensionId);
}

/**
 * Match Intercode Part 6 dynamic data formats:
 *   - `_<RICS>.ID1`  — numeric RICS code prefix (e.g. `_3703.ID1`)
 */
function isIntercodeDynamicData(dataFormat: string): boolean {
  return /^_\d+\.ID1$/.test(dataFormat);
}

/**
 * Match FCB Dynamic Content v1 format:
 *   - `FDC1`  — UicDynamicContentData (UIC barcode spec)
 */
function isFdc1(dataFormat: string): boolean {
  return dataFormat === 'FDC1';
}

// ---------------------------------------------------------------------------
// Hex / bytes helpers
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '').replace(/h$/i, '').toLowerCase();
  if (!/^[0-9a-f]*$/.test(clean)) throw new Error('Invalid hex characters');
  if (clean.length === 0) throw new Error('Hex input is empty');
  if (clean.length % 2 !== 0) throw new Error('Hex string must have even length');
  return new Uint8Array(clean.match(/.{1,2}/g)!.map(b => parseInt(b, 16)));
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Decode a UIC barcode ticket from a hex string.
 *
 * @param hex - The hex-encoded barcode payload (whitespace and trailing 'h' are stripped).
 * @returns A fully typed {@link UicBarcodeTicket} object.
 */
export function decodeTicket(hex: string): UicBarcodeTicket {
  const bytes = hexToBytes(hex);
  return decodeTicketFromBytes(bytes);
}

/**
 * Decode a UIC barcode ticket from raw bytes.
 *
 * @param bytes - The binary barcode payload.
 * @returns A fully typed {@link UicBarcodeTicket} object.
 */
export function decodeTicketFromBytes(bytes: Uint8Array): UicBarcodeTicket {
  // Step 1: Peek the header format using low-level BitBuffer
  const peekBuf = BitBuffer.from(bytes);
  peekBuf.readBit(); // skip optional bitmap (level2Signature present/absent)
  const format = SchemaBuilder.build({ type: 'IA5String' } as SchemaNode).decode(peekBuf) as string;

  const headerVersionMatch = format.match(/^U(\d+)$/);
  if (!headerVersionMatch) {
    throw new Error(`Unknown header format "${format}"`);
  }
  const headerVersion = parseInt(headerVersionMatch[1], 10);

  // Step 2: Decode the full header with version-specific schema
  const header = getHeaderCodec(headerVersion).decode(bytes) as any;

  const l2 = header.level2SignedData;
  const l1 = l2.level1Data;

  // Step 3: Extract security info
  const security: SecurityInfo = {
    securityProviderNum: l1.securityProviderNum,
    securityProviderIA5: l1.securityProviderIA5,
    keyId: l1.keyId,
    level1KeyAlg: l1.level1KeyAlg,
    level2KeyAlg: l1.level2KeyAlg,
    level1SigningAlg: l1.level1SigningAlg,
    level2SigningAlg: l1.level2SigningAlg,
    level2PublicKey: l1.level2PublicKey,
    level1Signature: l2.level1Signature,
    endOfValidityYear: l1.endOfValidityYear,
    endOfValidityDay: l1.endOfValidityDay,
    endOfValidityTime: l1.endOfValidityTime,
    validityDuration: l1.validityDuration,
  };

  // Step 4: Decode data blocks
  const railTickets: RailTicketData[] = [];
  const otherDataBlocks: DataBlock[] = [];

  for (const block of l1.dataSequence) {
    const fcbMatch = block.dataFormat.match(/^FCB(\d+)$/);
    if (fcbMatch) {
      const fcbVersion = parseInt(fcbMatch[1], 10);
      try {
        const codecs = getTicketCodecs(fcbVersion);
        const buf = BitBuffer.from(block.data);
        const raw = codecs.UicRailTicketData.decode(buf) as Record<string, unknown>;
        railTickets.push(decodeRailTicket(fcbVersion, raw));
      } catch {
        // If FCB decoding fails, add as raw block
        otherDataBlocks.push({ dataFormat: block.dataFormat, data: block.data });
      }
    } else {
      otherDataBlocks.push({ dataFormat: block.dataFormat, data: block.data });
    }
  }

  // Step 5: Decode Level 2 dynamic data
  let dynamicData: IntercodeDynamicData | undefined;
  let dynamicContentData: UicDynamicContentData | undefined;
  let level2DataBlock: DataBlock | undefined;

  if (l2.level2Data) {
    level2DataBlock = { dataFormat: l2.level2Data.dataFormat, data: l2.level2Data.data };
    if (isFdc1(l2.level2Data.dataFormat)) {
      try {
        dynamicContentData = getFdc1Codec().decode(l2.level2Data.data) as UicDynamicContentData;
      } catch {
        // leave as undefined if decoding fails
      }
    } else if (isIntercodeDynamicData(l2.level2Data.dataFormat)) {
      try {
        dynamicData = getIntercodeDynamicCodec().decode(l2.level2Data.data) as IntercodeDynamicData;
      } catch {
        // leave as undefined if decoding fails
      }
    }
  }

  return {
    format,
    headerVersion,
    level2Signature: header.level2Signature,
    security,
    railTickets,
    otherDataBlocks,
    dynamicData,
    dynamicContentData,
    level2DataBlock,
  };
}

// ---------------------------------------------------------------------------
// Rail ticket decoding helpers
// ---------------------------------------------------------------------------

function decodeRailTicket(fcbVersion: number, raw: Record<string, unknown>): RailTicketData {
  const issuingDetail = raw.issuingDetail ? decodeIssuingDetail(raw.issuingDetail as any) : undefined;
  const travelerDetail = raw.travelerDetail ? decodeTravelerDetail(raw.travelerDetail as any) : undefined;
  const transportDocument = raw.transportDocument
    ? decodeTransportDocuments(raw.transportDocument as any[])
    : undefined;
  const controlDetail = raw.controlDetail ? raw.controlDetail as ControlDetail : undefined;

  return {
    fcbVersion,
    issuingDetail,
    travelerDetail,
    transportDocument,
    controlDetail,
    raw,
  };
}

function decodeIssuingDetail(iss: any): IssuingDetail {
  const result: IssuingDetail = {
    securityProviderNum: iss.securityProviderNum,
    securityProviderIA5: iss.securityProviderIA5,
    issuerNum: iss.issuerNum,
    issuerIA5: iss.issuerIA5,
    issuingYear: iss.issuingYear,
    issuingDay: iss.issuingDay,
    issuingTime: iss.issuingTime,
    issuerName: iss.issuerName,
    specimen: iss.specimen ?? false,
    securePaperTicket: iss.securePaperTicket ?? false,
    activated: iss.activated ?? false,
    currency: iss.currency,
    currencyFract: iss.currencyFract,
    issuerPNR: iss.issuerPNR,
    issuedOnTrainNum: iss.issuedOnTrainNum,
    issuedOnTrainIA5: iss.issuedOnTrainIA5,
    issuedOnLine: iss.issuedOnLine,
    pointOfSale: iss.pointOfSale,
  };

  if (iss.extension) {
    const ext = iss.extension;
    if (isIntercodeIssuingExtension(ext.extensionId)) {
      try {
        const decoded = getIntercodeIssuingCodec().decode(ext.extensionData) as IntercodeIssuingData;
        decoded.extensionId = ext.extensionId;
        result.intercodeIssuing = decoded;
      } catch {
        result.extension = { extensionId: ext.extensionId, extensionData: ext.extensionData };
      }
    } else {
      result.extension = { extensionId: ext.extensionId, extensionData: ext.extensionData };
    }
  }

  return result;
}

function decodeTravelerDetail(td: any): TravelerDetail {
  return {
    traveler: td.traveler,
    preferredLanguage: td.preferredLanguage,
    groupName: td.groupName,
  };
}

function decodeTransportDocuments(docs: any[]): TransportDocumentEntry[] {
  return docs.map((doc) => {
    const ticket = doc.ticket || {};
    const entries = Object.entries(ticket);
    if (entries.length === 2 && entries[0][0] === 'key' && entries[1][0] === 'value') {
      // CHOICE decoded as { key: "variantName", value: {...} }
      return {
        ticketType: entries[0][1] as string,
        ticket: entries[1][1] as Record<string, unknown>,
      };
    }
    // Single-key CHOICE
    if (entries.length === 1) {
      return {
        ticketType: entries[0][0],
        ticket: entries[0][1] as Record<string, unknown>,
      };
    }
    return {
      ticketType: 'unknown',
      ticket,
    };
  });
}
