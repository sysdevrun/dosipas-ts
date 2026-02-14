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
import type { Codec } from 'asn1-per-ts';
import { HEADER_SCHEMAS, RAIL_TICKET_SCHEMAS, INTERCODE_SCHEMAS } from './schemas';
import type {
  UicBarcodeTicketInput,
  IssuingDetailInput,
  IntercodeIssuingDataInput,
  IntercodeDynamicDataInput,
  TransportDocumentInput,
} from './types';

// ---------------------------------------------------------------------------
// Codec caches (separate from decoder to avoid coupling)
// ---------------------------------------------------------------------------

const headerCodecCache = new Map<number, SchemaCodec>();
const ticketCodecCache = new Map<number, Record<string, Codec<unknown>>>();
let intercodeIssuingCodec: SchemaCodec | undefined;
let intercodeDynamicCodec: SchemaCodec | undefined;

function getHeaderCodec(version: number): SchemaCodec {
  let codec = headerCodecCache.get(version);
  if (codec) return codec;
  const schemas = HEADER_SCHEMAS[version];
  if (!schemas) throw new Error(`No schema for header v${version}`);
  codec = new SchemaCodec(schemas.UicBarcodeHeader as SchemaNode);
  headerCodecCache.set(version, codec);
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

  // Step 3: Build Level 2 data (Intercode dynamic)
  let level2Data: { dataFormat: string; data: Uint8Array } | undefined;
  if (input.dynamicData) {
    const dynamicBytes = getIntercodeDynamicCodec().encode({
      dynamicContentDay: input.dynamicData.dynamicContentDay ?? 0,
      dynamicContentTime: input.dynamicData.dynamicContentTime,
      dynamicContentUTCOffset: input.dynamicData.dynamicContentUTCOffset,
      dynamicContentDuration: input.dynamicData.dynamicContentDuration,
    });
    level2Data = {
      dataFormat: `_${input.dynamicData.rics}.ID1`,
      data: dynamicBytes,
    };
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
// Internal encoding helpers
// ---------------------------------------------------------------------------

function encodeRailTicket(fcbVersion: number, input: UicBarcodeTicketInput): Uint8Array {
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
      extensionId: `_${rics}II1`,
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
