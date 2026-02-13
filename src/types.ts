/**
 * TypeScript types for a decoded UIC barcode ticket with Intercode 6 extensions.
 *
 * The top-level type is {@link UicBarcodeTicket} which combines the header envelope,
 * decoded FCB rail ticket data, and Intercode 6 extension data into a single typed object.
 */

// ---------------------------------------------------------------------------
// Top-level decoded ticket
// ---------------------------------------------------------------------------

/** Fully decoded UIC barcode ticket with resolved Intercode 6 extensions. */
export interface UicBarcodeTicket {
  /** Header format string, e.g. "U1" or "U2". */
  format: string;
  /** Header version number (1 or 2). */
  headerVersion: number;
  /** Level 2 digital signature bytes, if present. */
  level2Signature?: Uint8Array;

  /** Security / key metadata from Level 1. */
  security: SecurityInfo;

  /** Decoded FCB rail ticket data blocks. */
  railTickets: RailTicketData[];

  /** Raw data blocks that were not identified as FCB. */
  otherDataBlocks: DataBlock[];

  /** Decoded Intercode 6 dynamic data from Level 2, if present. */
  dynamicData?: IntercodeDynamicData;

  /** Raw Level 2 data block, if present. */
  level2DataBlock?: DataBlock;
}

// ---------------------------------------------------------------------------
// Security info
// ---------------------------------------------------------------------------

export interface SecurityInfo {
  securityProviderNum?: number;
  securityProviderIA5?: string;
  keyId?: number;
  level1KeyAlg?: string;
  level2KeyAlg?: string;
  level1SigningAlg?: string;
  level2SigningAlg?: string;
  level2PublicKey?: Uint8Array;
  level1Signature?: Uint8Array;
  endOfValidityYear?: number;
  endOfValidityDay?: number;
  endOfValidityTime?: number;
  validityDuration?: number;
}

// ---------------------------------------------------------------------------
// Raw data block
// ---------------------------------------------------------------------------

export interface DataBlock {
  dataFormat: string;
  data: Uint8Array;
}

// ---------------------------------------------------------------------------
// FCB Rail Ticket Data
// ---------------------------------------------------------------------------

export interface RailTicketData {
  /** FCB version, e.g. 1, 2, or 3. */
  fcbVersion: number;
  /** Issuing details. */
  issuingDetail?: IssuingDetail;
  /** Traveler information. */
  travelerDetail?: TravelerDetail;
  /** Transport document entries. */
  transportDocument?: TransportDocumentEntry[];
  /** Control detail. */
  controlDetail?: ControlDetail;
  /** The raw decoded object (untyped) for fields not covered above. */
  raw: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Issuing detail
// ---------------------------------------------------------------------------

export interface IssuingDetail {
  securityProviderNum?: number;
  securityProviderIA5?: string;
  issuerNum?: number;
  issuerIA5?: string;
  issuingYear: number;
  issuingDay: number;
  issuingTime?: number;
  issuerName?: string;
  specimen: boolean;
  securePaperTicket: boolean;
  activated: boolean;
  currency?: string;
  currencyFract?: number;
  issuerPNR?: string;
  /** Decoded Intercode 6 issuing extension, if present. */
  intercodeIssuing?: IntercodeIssuingData;
  /** Raw extension data if present but not an Intercode extension. */
  extension?: ExtensionData;
}

export interface ExtensionData {
  extensionId: string;
  extensionData: Uint8Array;
}

// ---------------------------------------------------------------------------
// Intercode 6 types
// ---------------------------------------------------------------------------

export type RetailChannel =
  | 'smsTicket'
  | 'mobileApplication'
  | 'webSite'
  | 'ticketOffice'
  | 'depositaryTerminal'
  | 'onBoardTerminal'
  | 'ticketVendingMachine';

export interface ProductRetailerData {
  retailChannel?: RetailChannel;
  retailGeneratorId?: number;
  retailServerId?: number;
  retailerId?: number;
  retailPointId?: number;
}

export interface IntercodeIssuingData {
  intercodeVersion: number;
  intercodeInstanciation: number;
  networkId: Uint8Array;
  productRetailer?: ProductRetailerData;
}

export interface IntercodeDynamicData {
  dynamicContentDay: number;
  dynamicContentTime?: number;
  dynamicContentUTCOffset?: number;
  dynamicContentDuration?: number;
}

// ---------------------------------------------------------------------------
// Traveler detail
// ---------------------------------------------------------------------------

export interface TravelerDetail {
  traveler?: TravelerInfo[];
  preferredLanguage?: string;
  groupName?: string;
}

export interface TravelerInfo {
  firstName?: string;
  secondName?: string;
  lastName?: string;
  idCard?: string;
  passportId?: string;
  title?: string;
  gender?: string;
  customerIdIA5?: string;
  customerIdNum?: number;
  yearOfBirth?: number;
  monthOfBirth?: number;
  dayOfBirth?: number;
  ticketHolder?: boolean;
  passengerType?: string;
  passengerWithReducedMobility?: boolean;
  countryOfResidence?: number;
  countryOfPassport?: number;
  dateOfBirth?: string;
  status?: CustomerStatus[];
}

export interface CustomerStatus {
  statusProviderNum?: number;
  statusProviderIA5?: string;
  customerStatus?: number;
  customerStatusDescr?: string;
}

// ---------------------------------------------------------------------------
// Transport document
// ---------------------------------------------------------------------------

export interface TransportDocumentEntry {
  /** The variant name of the ticket CHOICE, e.g. "openTicket", "reservation", etc. */
  ticketType: string;
  /** Decoded ticket data (type depends on ticketType). */
  ticket: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Control detail
// ---------------------------------------------------------------------------

export interface ControlDetail {
  identificationByCardReference?: CardReference[];
  identificationByIdCard?: boolean;
  identificationByPassportId?: boolean;
  passportValidationRequired?: boolean;
  onlineValidationRequired?: boolean;
  ageCheckRequired?: boolean;
  reductionCardCheckRequired?: boolean;
  infoText?: string;
  includedTickets?: TicketLink[];
  extension?: ExtensionData;
}

export interface CardReference {
  trailingCardIdNum?: number;
  trailingCardIdIA5?: string;
  cardName?: string;
  cardIdNum?: number;
  cardIdIA5?: string;
  leadingCardIdNum?: number;
  leadingCardIdIA5?: string;
  cardTypeNum?: number;
  cardTypeDescr?: string;
}

export interface TicketLink {
  referenceIA5?: string;
  referenceNum?: number;
  issuerName?: string;
  issuerPNR?: string;
  productOwnerNum?: number;
  productOwnerIA5?: string;
  ticketType?: string;
  linkMode?: string;
}

// ---------------------------------------------------------------------------
// Encoding input types
// ---------------------------------------------------------------------------

/** Input for encoding a UIC barcode ticket. */
export interface UicBarcodeTicketInput {
  /** Header version (1 or 2). Default: 2. */
  headerVersion?: number;
  /** RICS code of the security provider. */
  securityProviderNum?: number;
  /** Key ID for signature verification. */
  keyId?: number;
  /** Level 1 key algorithm OID. */
  level1KeyAlg?: string;
  /** Level 2 key algorithm OID. */
  level2KeyAlg?: string;
  /** Level 1 signing algorithm OID. */
  level1SigningAlg?: string;
  /** Level 2 signing algorithm OID. */
  level2SigningAlg?: string;
  /** Level 2 public key bytes. */
  level2PublicKey?: Uint8Array;
  /** Level 1 signature bytes (placeholder). */
  level1Signature?: Uint8Array;
  /** Level 2 signature bytes (placeholder). */
  level2Signature?: Uint8Array;
  /** FCB version (1, 2 or 3). Default: 2. */
  fcbVersion?: number;
  /** The rail ticket data to encode. */
  railTicket: RailTicketInput;
  /** Intercode 6 dynamic data for Level 2. */
  dynamicData?: IntercodeDynamicDataInput;
}

export interface RailTicketInput {
  issuingDetail: IssuingDetailInput;
  travelerDetail?: TravelerDetailInput;
  transportDocument?: TransportDocumentInput[];
  controlDetail?: Record<string, unknown>;
}

export interface IssuingDetailInput {
  securityProviderNum?: number;
  issuerNum?: number;
  issuingYear: number;
  issuingDay: number;
  issuingTime?: number;
  issuerName?: string;
  specimen?: boolean;
  securePaperTicket?: boolean;
  activated?: boolean;
  currency?: string;
  currencyFract?: number;
  issuerPNR?: string;
  /** Intercode 6 issuing extension data. */
  intercodeIssuing?: IntercodeIssuingDataInput;
}

export interface IntercodeIssuingDataInput {
  intercodeVersion?: number;
  intercodeInstanciation?: number;
  networkId: Uint8Array;
  productRetailer?: ProductRetailerData;
}

export interface IntercodeDynamicDataInput {
  /** RICS code for the dataFormat field (e.g. 3703 → "_3703.ID1"). */
  rics: number;
  dynamicContentDay?: number;
  dynamicContentTime?: number;
  dynamicContentUTCOffset?: number;
  dynamicContentDuration?: number;
}

export interface TravelerDetailInput {
  traveler?: Partial<TravelerInfo>[];
  preferredLanguage?: string;
  groupName?: string;
}

export interface TransportDocumentInput {
  ticketType: string;
  ticket: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Signature verification types
// ---------------------------------------------------------------------------

/** Result of a signature verification attempt for a single level. */
export interface SignatureLevelResult {
  valid: boolean;
  error?: string;
  algorithm?: string;
}

/** Result of signature verification for both levels. */
export interface SignatureVerificationResult {
  level1: SignatureLevelResult;
  level2: SignatureLevelResult;
}

/** Options for signature verification. */
export interface VerifyOptions {
  /** Provider for Level 1 public keys (looked up by issuer + keyId). */
  level1KeyProvider?: Level1KeyProvider;
  /** Explicit Level 1 public key bytes (alternative to level1KeyProvider). */
  level1PublicKey?: Uint8Array;
}

/** Provider interface for looking up Level 1 public keys. */
export interface Level1KeyProvider {
  getPublicKey(
    securityProvider: { num?: number; ia5?: string },
    keyId: number,
    keyAlg?: string,
  ): Promise<Uint8Array>;
}
