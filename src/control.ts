/**
 * Ticket validity control helpers.
 *
 * Performs comprehensive validation of a dosipas ticket by decoding it once
 * and running a series of focused check functions — each responsible for
 * verifying one specific aspect of the ticket.
 */
import { decodeTicket } from './decoder';
import { verifyLevel1Signature, verifyLevel2Signature } from './verifier';
import { getEndOfValidityTime, getDynamicContentTime, getOpenTicketValidityWindow } from './time-helpers';
import type {
  UicBarcodeTicket,
  UicRailTicketData,
  UicDynamicContentData,
  IntercodeDynamicData,
  CheckResult,
  ControlResult,
  ControlOptions,
  OpenTicketData,
} from './types';

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '').replace(/h$/i, '').toLowerCase();
  return new Uint8Array(clean.match(/.{1,2}/g)!.map(b => parseInt(b, 16)));
}

// ---------------------------------------------------------------------------
// Accessor helpers — resolve new schema hierarchy
// ---------------------------------------------------------------------------

/** Infer header version from format string (U1→1, U2→2). */
function headerVersion(ticket: UicBarcodeTicket): number {
  const m = ticket.format.match(/^U(\d)$/);
  return m ? parseInt(m[1], 10) : 0;
}

/** Get the first decoded UicRailTicketData from dataSequence, if any. */
function firstRailTicket(ticket: UicBarcodeTicket): UicRailTicketData | undefined {
  for (const entry of ticket.level2SignedData.level1Data.dataSequence) {
    if (entry.decoded) return entry.decoded;
  }
  return undefined;
}

/** Get decoded level2 dynamic content, narrowed to FDC1. */
function fdc1Data(ticket: UicBarcodeTicket): UicDynamicContentData | undefined {
  const l2 = ticket.level2SignedData.level2Data;
  if (!l2 || l2.dataFormat !== 'FDC1') return undefined;
  return l2.decoded as UicDynamicContentData | undefined;
}

/** Get decoded level2 dynamic content, narrowed to Intercode. */
function intercodeDynamic(ticket: UicBarcodeTicket): IntercodeDynamicData | undefined {
  const l2 = ticket.level2SignedData.level2Data;
  if (!l2 || !/^_\d+\.ID1$/.test(l2.dataFormat)) return undefined;
  return l2.decoded as IntercodeDynamicData | undefined;
}

// ---------------------------------------------------------------------------
// Check helpers
// ---------------------------------------------------------------------------

function checkHeader(ticket: UicBarcodeTicket): CheckResult {
  const formatOk = ticket.format === 'U1' || ticket.format === 'U2';
  return {
    name: 'Header',
    passed: formatOk,
    severity: 'error',
    message: formatOk
      ? undefined
      : `Unrecognized header format: ${ticket.format}`,
  };
}

function checkSecurityInfo(ticket: UicBarcodeTicket): CheckResult {
  const l1 = ticket.level2SignedData.level1Data;
  const issues: string[] = [];

  // Level 1 (mandatory)
  if (l1.securityProviderNum == null && !l1.securityProviderIA5) {
    issues.push('missing security provider');
  }
  if (l1.keyId == null) {
    issues.push('missing keyId');
  }
  // level1SigningAlg is only available in v2 headers; v1 headers don't include OID fields
  if (headerVersion(ticket) >= 2 && !l1.level1SigningAlg) {
    issues.push('missing level1SigningAlg');
  }
  if (!ticket.level2SignedData.level1Signature) {
    issues.push('missing level1Signature');
  }

  // Level 2 (conditional)
  if (l1.level2SigningAlg) {
    if (!l1.level2KeyAlg) issues.push('level2SigningAlg set but missing level2KeyAlg');
    if (!l1.level2PublicKey) issues.push('level2SigningAlg set but missing level2PublicKey');
    if (!ticket.level2Signature) issues.push('level2SigningAlg set but missing level2Signature');
  }

  return {
    name: 'Security Info',
    passed: issues.length === 0,
    severity: 'error',
    message: issues.length > 0 ? issues.join('; ') : undefined,
  };
}

async function checkLevel1Signature(
  bytes: Uint8Array,
  ticket: UicBarcodeTicket,
  options: ControlOptions,
): Promise<CheckResult> {
  if (!options.level1KeyProvider) {
    return {
      name: 'Level 1 Signature',
      passed: false,
      severity: 'error',
      message: 'No level 1 key provider — cannot verify mandatory level 1 signature',
    };
  }

  try {
    const l1 = ticket.level2SignedData.level1Data;
    const pubKey = await options.level1KeyProvider.getPublicKey(
      { num: l1.securityProviderNum, ia5: l1.securityProviderIA5 },
      l1.keyId ?? 0,
      l1.level1KeyAlg,
    );
    const result = await verifyLevel1Signature(bytes, pubKey);
    return {
      name: 'Level 1 Signature',
      passed: result.valid,
      severity: 'error',
      message: result.valid ? undefined : (result.error ?? 'Verification failed'),
    };
  } catch (e: unknown) {
    return {
      name: 'Level 1 Signature',
      passed: false,
      severity: 'error',
      message: e instanceof Error ? e.message : 'Key provider error',
    };
  }
}

async function checkLevel2Signature(
  bytes: Uint8Array,
  ticket: UicBarcodeTicket,
): Promise<CheckResult> {
  if (!ticket.level2SignedData.level1Data.level2SigningAlg) {
    return {
      name: 'Level 2 Signature',
      passed: true,
      severity: 'info',
      message: 'Level 2 signature not required — level2SigningAlg not set',
    };
  }

  try {
    const result = await verifyLevel2Signature(bytes);
    return {
      name: 'Level 2 Signature',
      passed: result.valid,
      severity: 'error',
      message: result.valid ? undefined : (result.error ?? 'Verification failed'),
    };
  } catch (e: unknown) {
    return {
      name: 'Level 2 Signature',
      passed: false,
      severity: 'error',
      message: e instanceof Error ? e.message : 'Verification failed',
    };
  }
}

function checkNotExpired(ticket: UicBarcodeTicket, now: Date): CheckResult {
  const expiry = getEndOfValidityTime(ticket);
  if (!expiry) {
    return {
      name: 'Not Expired',
      passed: true,
      severity: 'info',
      message: 'Cannot determine expiry — no validity duration available',
    };
  }

  const passed = now < expiry;
  return {
    name: 'Not Expired',
    passed,
    severity: 'error',
    message: passed ? undefined : `Ticket expired at ${expiry.toISOString()}`,
  };
}

function checkNotSpecimen(ticket: UicBarcodeTicket): CheckResult {
  const specimen = firstRailTicket(ticket)?.issuingDetail?.specimen;
  return {
    name: 'Not Specimen',
    passed: !specimen,
    severity: 'error',
    message: specimen ? 'Ticket is a specimen/test ticket' : undefined,
  };
}

function checkActivated(ticket: UicBarcodeTicket): CheckResult {
  const activated = firstRailTicket(ticket)?.issuingDetail?.activated;
  return {
    name: 'Activated',
    passed: !!activated,
    severity: 'error',
    message: activated ? undefined : 'Ticket is not activated',
  };
}

function checkIssuingDetail(ticket: UicBarcodeTicket): CheckResult {
  const issues: string[] = [];
  const rt = firstRailTicket(ticket);

  if (!rt) {
    issues.push('no decoded rail ticket present');
  } else {
    if (!rt.issuingDetail) {
      issues.push('missing issuingDetail');
    } else {
      const iss = rt.issuingDetail;
      if (iss.issuingYear < 2016) issues.push(`implausible issuingYear: ${iss.issuingYear}`);
      if (iss.issuingDay < 1 || iss.issuingDay > 366) issues.push(`implausible issuingDay: ${iss.issuingDay}`);
    }
  }

  return {
    name: 'Issuing Detail',
    passed: issues.length === 0,
    severity: 'error',
    message: issues.length > 0 ? issues.join('; ') : undefined,
  };
}

function checkTransportDocument(ticket: UicBarcodeTicket): CheckResult {
  const docs = firstRailTicket(ticket)?.transportDocument;
  if (!docs || docs.length === 0) {
    return {
      name: 'Transport Document',
      passed: false,
      severity: 'error',
      message: 'No transport document present',
    };
  }

  // In new structure, each doc has ticket: { key, value } — check that key exists
  const invalid = docs.filter(d => !d.ticket?.key);
  if (invalid.length > 0) {
    return {
      name: 'Transport Document',
      passed: false,
      severity: 'error',
      message: `${invalid.length} transport document(s) missing ticket type`,
    };
  }

  return {
    name: 'Transport Document',
    passed: true,
    severity: 'error',
  };
}

function checkIntercodeExtension(
  ticket: UicBarcodeTicket,
  options: ControlOptions,
): CheckResult {
  const iss = firstRailTicket(ticket)?.issuingDetail;

  if (iss?.intercodeIssuing) {
    // Extension decoded successfully — check network ID if expected
    if (options.expectedIntercodeNetworkIds) {
      const networkHex = Array.from(iss.intercodeIssuing.networkId)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
      if (!options.expectedIntercodeNetworkIds.has(networkHex)) {
        return {
          name: 'Intercode Extension',
          passed: false,
          severity: 'error',
          message: `Network ID ${networkHex} not in expected set: ${[...options.expectedIntercodeNetworkIds].join(', ')}`,
        };
      }
    }
    return {
      name: 'Intercode Extension',
      passed: true,
      severity: options.expectedIntercodeNetworkIds ? 'error' : 'warning',
    };
  }

  if (iss?.extension) {
    const extId = iss.extension.extensionId;
    if (/^[_+](\d+|[A-Z]{2})II1$/.test(extId)) {
      return {
        name: 'Intercode Extension',
        passed: false,
        severity: options.expectedIntercodeNetworkIds ? 'error' : 'warning',
        message: `Extension ${extId} looks like Intercode but was not decoded`,
      };
    }
  }

  if (options.expectedIntercodeNetworkIds) {
    return {
      name: 'Intercode Extension',
      passed: false,
      severity: 'error',
      message: 'Intercode issuing data required but absent',
    };
  }

  return {
    name: 'Intercode Extension',
    passed: true,
    severity: 'info',
    message: 'No issuing extension present',
  };
}

function checkDynamicData(ticket: UicBarcodeTicket): CheckResult {
  const l2 = ticket.level2SignedData.level2Data;

  if (!l2) {
    return {
      name: 'Dynamic Data',
      passed: true,
      severity: 'info',
      message: 'No level 2 data block present',
    };
  }

  // FDC1 format
  if (l2.dataFormat === 'FDC1') {
    if (!l2.decoded) {
      return {
        name: 'Dynamic Data',
        passed: false,
        severity: 'warning',
        message: 'FDC1 data block present but decoding failed',
      };
    }
    return { name: 'Dynamic Data', passed: true, severity: 'warning' };
  }

  // Intercode _RICS.ID1 format
  if (/^_\d+\.ID1$/.test(l2.dataFormat)) {
    if (!l2.decoded) {
      return {
        name: 'Dynamic Data',
        passed: false,
        severity: 'warning',
        message: `${l2.dataFormat} data block present but decoding failed`,
      };
    }
    return { name: 'Dynamic Data', passed: true, severity: 'warning' };
  }

  return {
    name: 'Dynamic Data',
    passed: true,
    severity: 'info',
    message: `Unknown level 2 data format: ${l2.dataFormat}`,
  };
}

function checkDynamicContentFreshness(
  ticket: UicBarcodeTicket,
  now: Date,
): CheckResult {
  const l1 = ticket.level2SignedData.level1Data;

  const genTime = getDynamicContentTime(ticket);
  if (!genTime) {
    // No dynamic content or required fields missing
    const l2 = ticket.level2SignedData.level2Data;
    if (!l2?.decoded) {
      return {
        name: 'Dynamic Content Freshness',
        passed: true,
        severity: 'info',
        message: 'No dynamic content present',
      };
    }
    return {
      name: 'Dynamic Content Freshness',
      passed: true,
      severity: 'info',
      message: 'Cannot compute freshness — missing fields',
    };
  }

  // Determine duration: for Intercode, prefer dynamicContentDuration, then validityDuration
  let durationMs: number | undefined;
  const dd = intercodeDynamic(ticket);
  if (dd?.dynamicContentDuration != null) {
    durationMs = dd.dynamicContentDuration * 1000;
  } else if (l1.validityDuration != null) {
    durationMs = l1.validityDuration * 1000;
  }

  if (durationMs == null) {
    return {
      name: 'Dynamic Content Freshness',
      passed: true,
      severity: 'info',
      message: 'Cannot compute freshness — no duration available',
    };
  }

  const expiryTime = new Date(genTime.getTime() + durationMs);
  const passed = now < expiryTime;

  return {
    name: 'Dynamic Content Freshness',
    passed,
    severity: 'error',
    message: passed
      ? undefined
      : `Dynamic content expired at ${expiryTime.toISOString()}`,
  };
}

// ---------------------------------------------------------------------------
// Zone & carrier check helpers
// ---------------------------------------------------------------------------

/** Get all openTicket transport documents from the first rail ticket. */
function getOpenTickets(ticket: UicBarcodeTicket): OpenTicketData[] {
  const docs = firstRailTicket(ticket)?.transportDocument;
  if (!docs) return [];
  return docs
    .filter((d): d is { ticket: { key: 'openTicket'; value: OpenTicketData } } & typeof d =>
      d.ticket.key === 'openTicket')
    .map(d => d.ticket.value);
}

/** Check whether an open ticket authorizes ALL expected carriers. */
function carriersMatch(
  ot: OpenTicketData,
  expected: Array<number | string>,
): boolean {
  return expected.every(carrier => {
    // Check top-level OpenTicketData carrier lists
    if (typeof carrier === 'number') {
      if (ot.carrierNum?.includes(carrier)) return true;
      if (ot.productOwnerNum === carrier) return true;
    } else {
      if (ot.carrierIA5?.includes(carrier)) return true;
      if (ot.productOwnerIA5 === carrier) return true;
    }

    // Check validRegion entries for carrier
    if (ot.validRegion) {
      for (const region of ot.validRegion) {
        if (region.key === 'zones' || region.key === 'lines') {
          if (typeof carrier === 'number' && region.value.carrierNum === carrier) return true;
          if (typeof carrier === 'string' && region.value.carrierIA5 === carrier) return true;
        } else if (region.key === 'viaStations') {
          if (typeof carrier === 'number' && region.value.carrierNum?.includes(carrier)) return true;
          if (typeof carrier === 'string' && region.value.carrierIA5?.includes(carrier)) return true;
        }
      }
    }
    return false;
  });
}

/** Check whether an open ticket authorizes ALL expected zones. */
function zonesMatch(
  ot: OpenTicketData,
  expected: Array<number | string>,
): boolean {
  if (!ot.validRegion) return false;

  const allZoneIds = new Set<number>();
  const allNutsCodes = new Set<string>();

  for (const region of ot.validRegion) {
    if (region.key !== 'zones') continue;
    if (region.value.zoneId) region.value.zoneId.forEach(id => allZoneIds.add(id));
    if (region.value.nutsCode) allNutsCodes.add(region.value.nutsCode);
  }

  return expected.every(zone => {
    if (typeof zone === 'number') return allZoneIds.has(zone);
    return allNutsCodes.has(zone);
  });
}

function checkZonesAndCarriers(
  ticket: UicBarcodeTicket,
  options: ControlOptions,
): CheckResult {
  const expectedCarriers = options.expectedCarriers;
  const expectedZones = options.expectedZones;

  if (!expectedCarriers?.length && !expectedZones?.length) {
    return {
      name: 'Zones & Carriers',
      passed: true,
      severity: 'info',
      message: 'No zone/carrier constraints specified',
    };
  }

  const openTickets = getOpenTickets(ticket);
  if (openTickets.length === 0) {
    return {
      name: 'Zones & Carriers',
      passed: false,
      severity: 'error',
      message: 'No openTicket transport documents found',
    };
  }

  for (const ot of openTickets) {
    const carrierOk = !expectedCarriers?.length || carriersMatch(ot, expectedCarriers);
    const zonesOk   = !expectedZones?.length    || zonesMatch(ot, expectedZones);
    if (carrierOk && zonesOk) {
      return {
        name: 'Zones & Carriers',
        passed: true,
        severity: 'error',
      };
    }
  }

  const issues: string[] = [];
  if (expectedCarriers?.length) issues.push(`carriers: ${expectedCarriers.join(', ')}`);
  if (expectedZones?.length)    issues.push(`zones: ${expectedZones.join(', ')}`);

  return {
    name: 'Zones & Carriers',
    passed: false,
    severity: 'error',
    message: `No openTicket covers the expected ${issues.join(' and ')}`,
  };
}

// ---------------------------------------------------------------------------
// Open ticket validity window check
// ---------------------------------------------------------------------------

function checkOpenTicketValidity(
  ticket: UicBarcodeTicket,
  now: Date,
): CheckResult {
  const openTickets = getOpenTickets(ticket);
  if (openTickets.length === 0) {
    return {
      name: 'Open Ticket Validity',
      passed: true,
      severity: 'info',
      message: 'No openTicket transport documents — skipping validity window check',
    };
  }

  const issuingDetail = firstRailTicket(ticket)?.issuingDetail;
  if (!issuingDetail) {
    return {
      name: 'Open Ticket Validity',
      passed: true,
      severity: 'info',
      message: 'Cannot determine validity window — missing issuingDetail',
    };
  }

  const nowMs = now.getTime();
  const windows: Array<{ validFrom: Date; validUntil: Date }> = [];

  for (const ot of openTickets) {
    const window = getOpenTicketValidityWindow(ot, issuingDetail);
    if (!window) continue;
    windows.push(window);
    if (window.validFrom.getTime() <= nowMs && nowMs <= window.validUntil.getTime()) {
      return {
        name: 'Open Ticket Validity',
        passed: true,
        severity: 'error',
      };
    }
  }

  if (windows.length === 0) {
    return {
      name: 'Open Ticket Validity',
      passed: true,
      severity: 'info',
      message: 'Cannot determine validity window — missing issuingDetail fields',
    };
  }

  const windowDescs = windows
    .map(w => `${w.validFrom.toISOString()} → ${w.validUntil.toISOString()}`)
    .join(', ');

  return {
    name: 'Open Ticket Validity',
    passed: false,
    severity: 'error',
    message: `Current time ${now.toISOString()} is outside validity window(s): ${windowDescs}`,
  };
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/**
 * Perform comprehensive validation of a dosipas ticket.
 *
 * Decodes the ticket from hex, then runs a series of check functions covering
 * header format, security metadata, signatures, expiry, specimen/activated
 * flags, issuing details, transport documents, Intercode extensions, and
 * dynamic content freshness.
 *
 * @param hex - Hex-encoded barcode payload.
 * @param options - Control options (reference time, key provider, expected networks).
 * @returns Aggregated control result with individual check results.
 */
export async function controlTicket(
  hex: string,
  options?: ControlOptions,
): Promise<ControlResult> {
  const checks: Record<string, CheckResult> = {};
  const opts = options ?? {};
  const now = opts.now ?? new Date();

  // 1. Decode
  let ticket: UicBarcodeTicket;
  try {
    ticket = decodeTicket(hex);
    checks.decode = {
      name: 'Decode',
      passed: true,
      severity: 'error',
    };
  } catch (e: unknown) {
    checks.decode = {
      name: 'Decode',
      passed: false,
      severity: 'error',
      message: e instanceof Error ? e.message : 'Decode failed',
    };
    return { valid: false, checks };
  }

  // Convert hex to bytes for signature verification
  const bytes = hexToBytes(hex);

  // 2. Header
  checks.header = checkHeader(ticket);

  // 3. Security Info
  checks.securityInfo = checkSecurityInfo(ticket);

  // 4. Level 1 Signature (async)
  checks.level1Signature = await checkLevel1Signature(bytes, ticket, opts);

  // 5. Level 2 Signature (async)
  checks.level2Signature = await checkLevel2Signature(bytes, ticket);

  // 6. Not Expired
  checks.notExpired = checkNotExpired(ticket, now);

  // 7. Not Specimen
  checks.notSpecimen = checkNotSpecimen(ticket);

  // 8. Activated
  checks.activated = checkActivated(ticket);

  // 9. Issuing Detail
  checks.issuingDetail = checkIssuingDetail(ticket);

  // 10. Transport Document
  checks.transportDocument = checkTransportDocument(ticket);

  // 11. Intercode Extension
  checks.intercodeExtension = checkIntercodeExtension(ticket, opts);

  // 12. Dynamic Data
  checks.dynamicData = checkDynamicData(ticket);

  // 13. Dynamic Content Freshness
  checks.dynamicContentFreshness = checkDynamicContentFreshness(ticket, now);

  // 14. Zones & Carriers
  checks.zonesAndCarriers = checkZonesAndCarriers(ticket, opts);

  // 15. Open Ticket Validity Window
  checks.openTicketValidity = checkOpenTicketValidity(ticket, now);

  // Compute overall validity: all error-severity checks must pass
  const valid = Object.values(checks).every(
    c => c.severity !== 'error' || c.passed,
  );

  return { valid, ticket, checks };
}
