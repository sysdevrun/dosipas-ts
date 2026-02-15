export { decodeTicket, decodeTicketFromBytes } from './decoder';
export { encodeTicket, encodeTicketToBytes } from './encoder';
export { verifySignatures, verifyLevel1Signature, verifyLevel2Signature, findKeyInXml, parseKeysXml } from './verifier';
export { extractSignedData } from './signed-data';
export { signLevel1, signLevel2, signAndEncodeTicket, generateKeyPair, getPublicKey, CURVES } from './signer';
export { SAMPLE_TICKET_HEX, SNCF_TER_TICKET_HEX, SOLEA_TICKET_HEX, BUS_ARDECHE_TICKET_HEX, CTS_TICKET_HEX, GRAND_EST_U1_FCB3_HEX } from './fixtures';
export { SNCF_TER_SIGNATURES, SOLEA_SIGNATURES, CTS_SIGNATURES } from './signature-fixtures';

export type {
  UicBarcodeTicket,
  SecurityInfo,
  DataBlock,
  RailTicketData,
  IssuingDetail,
  GeoCoordinate,
  ExtensionData,
  IntercodeIssuingData,
  IntercodeDynamicData,
  RetailChannel,
  ProductRetailerData,
  TravelerDetail,
  TravelerInfo,
  CustomerStatus,
  TransportDocumentEntry,
  ControlDetail,
  CardReference,
  TicketLink,
  UicBarcodeTicketInput,
  RailTicketInput,
  IssuingDetailInput,
  IntercodeIssuingDataInput,
  IntercodeDynamicDataInput,
  TravelerDetailInput,
  TransportDocumentInput,
  SignatureVerificationResult,
  SignatureLevelResult,
  VerifyOptions,
  Level1KeyProvider,
} from './types';

export type { UicPublicKeyEntry } from './verifier';
export type { ExtractedSignedData } from './signed-data';
export type { CurveName, CurveConfig, SigningKeyPair } from './signer';
