export { decodeTicket, decodeTicketFromBytes } from './decoder';
export { encodeTicket, encodeTicketToBytes } from './encoder';
export { verifySignatures, verifyLevel1Signature, verifyLevel2Signature, findKeyInXml, parseKeysXml } from './verifier';
export { controlTicket } from './control';
export { getIssuingTime, getEndOfValidityTime, getDynamicContentTime } from './time-helpers';
export { extractSignedData } from './signed-data';
export { signLevel1, signLevel2, signAndEncodeTicket, generateKeyPair, getPublicKey, CURVES } from './signer';
export { SAMPLE_TICKET_HEX, SNCF_TER_TICKET_HEX, SOLEA_TICKET_HEX, BUS_ARDECHE_TICKET_HEX, BUS_AIN_TICKET_HEX, DROME_BUS_TICKET_HEX, CTS_TICKET_HEX, GRAND_EST_U1_FCB3_HEX } from './fixtures';
export { SNCF_TER_SIGNATURES, SOLEA_SIGNATURES, CTS_SIGNATURES } from './signature-fixtures';

export type {
  UicBarcodeTicket,
  Level2SignedData,
  Level1Data,
  DataSequenceEntry,
  Level2Data,
  UicRailTicketData,
  IssuingDetail,
  GeoCoordinate,
  ExtensionData,
  TransportDocumentData,
  IntercodeIssuingData,
  IntercodeDynamicData,
  UicDynamicContentData,
  TimeStampData,
  DynamicContentGeoCoordinate,
  DynamicContentExtensionData,
  RetailChannel,
  ProductRetailerData,
  TravelerDetail,
  TravelerInfo,
  CustomerStatus,
  ControlDetail,
  CardReference,
  TicketLink,
  UicBarcodeTicketInput,
  RailTicketInput,
  IssuingDetailInput,
  IntercodeIssuingDataInput,
  IntercodeDynamicDataInput,
  UicDynamicContentDataInput,
  TravelerDetailInput,
  TransportDocumentInput,
  SignatureVerificationResult,
  SignatureLevelResult,
  VerifyOptions,
  Level1KeyProvider,
  ControlOptions,
  ControlResult,
  CheckResult,
} from './types';

export type { UicPublicKeyEntry } from './verifier';
export type { ExtractedSignedData } from './signed-data';
export type { CurveName, CurveConfig, SigningKeyPair } from './signer';
