/**
 * TypeScript types for a decoded UIC barcode ticket with Intercode 6 extensions.
 *
 * The top-level type is {@link UicBarcodeTicket} which follows the exact
 * `UicBarcodeHeader` ASN.1 schema hierarchy, with decoded sub-structures
 * available on `dataSequence[i].decoded` and `level2Data.decoded`.
 */

// ---------------------------------------------------------------------------
// UicBarcodeHeader — matches ASN.1 schema
// ---------------------------------------------------------------------------

/** Decoded UIC barcode ticket. Follows the UicBarcodeHeader ASN.1 schema. */
export interface UicBarcodeTicket {
  /** Header format string, e.g. "U1" or "U2". */
  format: string;
  /** Level 2 signed data (contains level1Data, level1Signature, level2Data). */
  level2SignedData: Level2SignedData;
  /** Level 2 digital signature bytes, if present. */
  level2Signature?: Uint8Array;
}

/** Level2DataType — matches ASN.1 schema. */
export interface Level2SignedData {
  /** Level 1 data (security metadata + data sequence). */
  level1Data: Level1Data;
  /** Level 1 digital signature bytes. */
  level1Signature?: Uint8Array;
  /** Level 2 data block (dynamic content). */
  level2Data?: Level2Data;
}

/** Level1DataType — matches ASN.1 schema. */
export interface Level1Data {
  securityProviderNum?: number;
  securityProviderIA5?: string;
  keyId?: number;
  dataSequence: DataSequenceEntry[];
  level1KeyAlg?: string;
  level2KeyAlg?: string;
  level1SigningAlg?: string;
  level2SigningAlg?: string;
  level2PublicKey?: Uint8Array;
  endOfValidityYear?: number;
  endOfValidityDay?: number;
  endOfValidityTime?: number;
  validityDuration?: number;
}

/** DataType — matches ASN.1 schema, extended with optional decoded content. */
export interface DataSequenceEntry {
  /** Data format identifier (e.g. "FCB1", "FCB2", "FCB3"). */
  dataFormat: string;
  /** Raw PER-encoded data bytes. */
  data: Uint8Array;
  /** Decoded UicRailTicketData (when dataFormat is FCBn). */
  decoded?: UicRailTicketData;
}

/** DataType for level2Data — matches ASN.1 schema, extended with optional decoded content. */
export interface Level2Data {
  /** Data format identifier (e.g. "FDC1", "_3703.ID1"). */
  dataFormat: string;
  /** Raw PER-encoded data bytes. */
  data: Uint8Array;
  /** Decoded dynamic content data (UicDynamicContentData for FDC1, IntercodeDynamicData for _RICS.ID1). */
  decoded?: UicDynamicContentData | IntercodeDynamicData;
}

// ---------------------------------------------------------------------------
// UicRailTicketData — matches ASN.1 schema
// ---------------------------------------------------------------------------

/** Decoded FCB rail ticket data. Matches UicRailTicketData ASN.1 schema. */
export interface UicRailTicketData {
  issuingDetail?: IssuingDetail;
  travelerDetail?: TravelerDetail;
  transportDocument?: TransportDocumentData[];
  controlDetail?: ControlDetail;
}

// ---------------------------------------------------------------------------
// Issuing detail — matches ASN.1 schema
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
  issuedOnTrainNum?: number;
  issuedOnTrainIA5?: string;
  issuedOnLine?: number;
  pointOfSale?: GeoCoordinate;
  /** Raw extension data as defined in the ASN.1 schema. */
  extension?: ExtensionData;
  /** Decoded Intercode 6 issuing extension (when extension is recognized as Intercode). */
  intercodeIssuing?: IntercodeIssuingData;
}

export interface GeoCoordinate {
  geoUnit?: number;
  coordinateSystem?: number;
  hemisphereLongitude?: number;
  hemisphereLatitude?: number;
  longitude?: number;
  latitude?: number;
  accuracy?: number;
}

export interface ExtensionData {
  extensionId: string;
  extensionData: Uint8Array;
}

// ---------------------------------------------------------------------------
// Transport document — matches ASN.1 schema
// ---------------------------------------------------------------------------

/** Transport document entry. Matches the SEQUENCE { token, ticket } in the schema. */
export interface TransportDocumentData {
  /** Token data (optional in schema). */
  token?: Record<string, unknown>;
  /** The CHOICE-encoded ticket (variant name as `key`, variant data as `value`). */
  ticket: { key: string; value: Record<string, unknown> };
}

// ---------------------------------------------------------------------------
// Traveler detail — matches ASN.1 schema
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
  /** Day-of-year (0-370). FCB v1 only. */
  dayOfBirth?: number;
  /** Day-of-month (1-31). FCB v2/v3 only. */
  dayOfBirthInMonth?: number;
  ticketHolder?: boolean;
  passengerType?: string;
  passengerWithReducedMobility?: boolean;
  countryOfResidence?: number;
  countryOfPassport?: number;
  countryOfIdCard?: number;
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
// Control detail — matches ASN.1 schema
// ---------------------------------------------------------------------------

export interface ControlDetail {
  identificationByCardReference?: CardReference[];
  identificationByIdCard?: boolean;
  identificationByPassportId?: boolean;
  identificationItem?: number;
  passportValidationRequired?: boolean;
  onlineValidationRequired?: boolean;
  randomDetailedValidationRequired?: boolean;
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
// Intercode 6 types — matches intercode6.schema.json
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
  /** Original extension ID string (e.g. "_3703II1" or "+FRII1"). */
  extensionId: string;
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
// UIC Dynamic Content Data (FDC1) — matches uicDynamicContentData_v1.schema.json
// ---------------------------------------------------------------------------

export interface TimeStampData {
  day: number;
  time: number;
}

export interface DynamicContentGeoCoordinate {
  geoUnit?: string;
  coordinateSystem?: string;
  hemisphereLongitude?: string;
  hemisphereLatitude?: string;
  longitude: number;
  latitude: number;
  accuracy?: string;
}

export interface DynamicContentExtensionData {
  extensionId: string;
  extensionData: Uint8Array;
}

/** Decoded UIC Dynamic Content Data v1 (FDC1 format). */
export interface UicDynamicContentData {
  dynamicContentMobileAppId?: string;
  dynamicContentTimeStamp?: TimeStampData;
  dynamicContentGeoCoordinate?: DynamicContentGeoCoordinate;
  dynamicContentResponseToChallenge?: DynamicContentExtensionData[];
  dynamicContentExtension?: DynamicContentExtensionData;
}

// ---------------------------------------------------------------------------
// Encoding input types (flat structure for convenience)
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
  /** End of validity year (2016-2269, v2 header only). */
  endOfValidityYear?: number;
  /** End of validity day (1-366). */
  endOfValidityDay?: number;
  /** End of validity time in minutes (0-1439). */
  endOfValidityTime?: number;
  /** Validity duration in minutes (1-3600). */
  validityDuration?: number;
  /** FCB version (1, 2 or 3). Default: 2. */
  fcbVersion?: number;
  /** The rail ticket data to encode. */
  railTicket: RailTicketInput;
  /** Intercode 6 dynamic data for Level 2 (encoded as _RICS.ID1). */
  dynamicData?: IntercodeDynamicDataInput;
  /** UIC Dynamic Content Data for Level 2 (encoded as FDC1). */
  dynamicContentData?: UicDynamicContentDataInput;
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
  /** Override the generated extension ID (e.g. "+FRII1"). When omitted, defaults to `_<RICS>II1`. */
  extensionId?: string;
  intercodeVersion?: number;
  intercodeInstanciation?: number;
  networkId: Uint8Array;
  productRetailer?: ProductRetailerData;
}

export interface IntercodeDynamicDataInput {
  /** RICS code for the dataFormat field (e.g. 3703 -> "_3703.ID1"). */
  rics: number;
  dynamicContentDay?: number;
  dynamicContentTime?: number;
  dynamicContentUTCOffset?: number;
  dynamicContentDuration?: number;
}

/** Input for encoding UIC Dynamic Content Data (FDC1 format). */
export interface UicDynamicContentDataInput {
  dynamicContentMobileAppId?: string;
  dynamicContentTimeStamp?: TimeStampData;
  dynamicContentGeoCoordinate?: DynamicContentGeoCoordinate;
  dynamicContentResponseToChallenge?: DynamicContentExtensionData[];
  dynamicContentExtension?: DynamicContentExtensionData;
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
// Ticket control types
// ---------------------------------------------------------------------------

/** Options for ticket control / validation. */
export interface ControlOptions {
  /** Reference date/time for temporal checks. Defaults to `new Date()`. */
  now?: Date;
  /** Level 1 key provider callback for signature verification. */
  level1KeyProvider?: Level1KeyProvider;
  /**
   * Set of expected Intercode network IDs (hex strings, e.g. "250502").
   * When provided, intercodeIssuing must be present and its networkId must
   * match one of the expected values.
   */
  expectedIntercodeNetworkIds?: Set<string>;
}

/** Result of a single validation check. */
export interface CheckResult {
  name: string;
  passed: boolean;
  severity: 'error' | 'warning' | 'info';
  message?: string;
}

/** Aggregated control result for a ticket. */
export interface ControlResult {
  /** True only if every check with severity 'error' passed. */
  valid: boolean;
  /** The decoded ticket (undefined if decoding failed). */
  ticket?: UicBarcodeTicket;
  /** Individual check results keyed by check name. */
  checks: Record<string, CheckResult>;
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
