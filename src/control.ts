/**
 * Ticket validity control helpers.
 *
 * Performs comprehensive validation of a dosipas ticket by decoding it once
 * and running a series of focused check functions — each responsible for
 * verifying one specific aspect of the ticket.
 */
import { decodeTicket } from './decoder';
import { verifyLevel1Signature, verifyLevel2Signature } from './verifier';
import type {
  UicBarcodeTicket,
  CheckResult,
  ControlResult,
  ControlOptions,
} from './types';

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '').replace(/h$/i, '').toLowerCase();
  return new Uint8Array(clean.match(/.{1,2}/g)!.map(b => parseInt(b, 16)));
}

// ---------------------------------------------------------------------------
// Check helpers
// ---------------------------------------------------------------------------

function checkHeader(ticket: UicBarcodeTicket): CheckResult {
  const formatOk = ticket.format === 'U1' || ticket.format === 'U2';
  const versionOk = ticket.headerVersion === 1 || ticket.headerVersion === 2;
  const passed = formatOk && versionOk;
  return {
    name: 'Header',
    passed,
    severity: 'error',
    message: passed
      ? undefined
      : `Unrecognized header: format=${ticket.format}, version=${ticket.headerVersion}`,
  };
}

function checkSecurityInfo(ticket: UicBarcodeTicket): CheckResult {
  const s = ticket.security;
  const issues: string[] = [];

  // Level 1 (mandatory)
  if (s.securityProviderNum == null && !s.securityProviderIA5) {
    issues.push('missing security provider');
  }
  if (s.keyId == null) {
    issues.push('missing keyId');
  }
  // level1SigningAlg is only available in v2 headers; v1 headers don't include OID fields
  if (ticket.headerVersion >= 2 && !s.level1SigningAlg) {
    issues.push('missing level1SigningAlg');
  }
  if (!s.level1Signature) {
    issues.push('missing level1Signature');
  }

  // Level 2 (conditional)
  if (s.level2SigningAlg) {
    if (!s.level2KeyAlg) issues.push('level2SigningAlg set but missing level2KeyAlg');
    if (!s.level2PublicKey) issues.push('level2SigningAlg set but missing level2PublicKey');
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
    const s = ticket.security;
    const pubKey = await options.level1KeyProvider.getPublicKey(
      { num: s.securityProviderNum, ia5: s.securityProviderIA5 },
      s.keyId ?? 0,
      s.level1KeyAlg,
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
  if (!ticket.security.level2SigningAlg) {
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
  const s = ticket.security;

  if (ticket.headerVersion === 2 && s.endOfValidityYear != null && s.endOfValidityDay != null) {
    // v2 header: compute expiry from end-of-validity fields
    const year = s.endOfValidityYear;
    const day = s.endOfValidityDay;
    const timeMinutes = s.endOfValidityTime ?? 0;
    const durationMinutes = s.validityDuration ?? 0;

    // Compute date from year + day-of-year
    const expiry = new Date(Date.UTC(year, 0, day, 0, timeMinutes + durationMinutes));
    const passed = now < expiry;
    return {
      name: 'Not Expired',
      passed,
      severity: 'error',
      message: passed ? undefined : `Ticket expired at ${expiry.toISOString()}`,
    };
  }

  // v1 header: use issuing date + validityDuration
  const rt = ticket.railTickets[0];
  const iss = rt?.issuingDetail;
  if (iss && s.validityDuration != null) {
    const issuingDate = new Date(Date.UTC(iss.issuingYear, 0, iss.issuingDay));
    const expiry = new Date(issuingDate.getTime() + s.validityDuration * 60 * 1000);
    const passed = now < expiry;
    return {
      name: 'Not Expired',
      passed,
      severity: 'error',
      message: passed ? undefined : `Ticket expired at ${expiry.toISOString()}`,
    };
  }

  return {
    name: 'Not Expired',
    passed: true,
    severity: 'info',
    message: 'Cannot determine expiry — no validity duration available',
  };
}

function checkNotSpecimen(ticket: UicBarcodeTicket): CheckResult {
  const specimen = ticket.railTickets[0]?.issuingDetail?.specimen;
  return {
    name: 'Not Specimen',
    passed: !specimen,
    severity: 'error',
    message: specimen ? 'Ticket is a specimen/test ticket' : undefined,
  };
}

function checkActivated(ticket: UicBarcodeTicket): CheckResult {
  const activated = ticket.railTickets[0]?.issuingDetail?.activated;
  return {
    name: 'Activated',
    passed: !!activated,
    severity: 'error',
    message: activated ? undefined : 'Ticket is not activated',
  };
}

function checkIssuingDetail(ticket: UicBarcodeTicket): CheckResult {
  const issues: string[] = [];

  if (ticket.railTickets.length === 0) {
    issues.push('no rail ticket present');
  } else {
    const rt = ticket.railTickets[0];
    if (!rt.issuingDetail) {
      issues.push('missing issuingDetail');
    } else {
      const iss = rt.issuingDetail;
      if (iss.issuingYear < 2016) issues.push(`implausible issuingYear: ${iss.issuingYear}`);
      if (iss.issuingDay < 1 || iss.issuingDay > 366) issues.push(`implausible issuingDay: ${iss.issuingDay}`);
      if (iss.issuerNum == null && !iss.issuerIA5) issues.push('missing issuer');
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
  const docs = ticket.railTickets[0]?.transportDocument;
  if (!docs || docs.length === 0) {
    return {
      name: 'Transport Document',
      passed: false,
      severity: 'error',
      message: 'No transport document present',
    };
  }

  const invalid = docs.filter(d => !d.ticketType);
  if (invalid.length > 0) {
    return {
      name: 'Transport Document',
      passed: false,
      severity: 'error',
      message: `${invalid.length} transport document(s) missing ticketType`,
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
  const iss = ticket.railTickets[0]?.issuingDetail;

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
  if (!ticket.level2DataBlock) {
    return {
      name: 'Dynamic Data',
      passed: true,
      severity: 'info',
      message: 'No level 2 data block present',
    };
  }

  // FDC1 format
  if (ticket.level2DataBlock.dataFormat === 'FDC1') {
    if (!ticket.dynamicContentData) {
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
  if (/^_\d+\.ID1$/.test(ticket.level2DataBlock.dataFormat)) {
    if (!ticket.dynamicData) {
      return {
        name: 'Dynamic Data',
        passed: false,
        severity: 'warning',
        message: `${ticket.level2DataBlock.dataFormat} data block present but decoding failed`,
      };
    }
    return { name: 'Dynamic Data', passed: true, severity: 'warning' };
  }

  return {
    name: 'Dynamic Data',
    passed: true,
    severity: 'info',
    message: `Unknown level 2 data format: ${ticket.level2DataBlock.dataFormat}`,
  };
}

function checkDynamicContentFreshness(
  ticket: UicBarcodeTicket,
  now: Date,
): CheckResult {
  const iss = ticket.railTickets[0]?.issuingDetail;

  // FDC1 dynamic content
  if (ticket.dynamicContentData?.dynamicContentTimeStamp) {
    const ts = ticket.dynamicContentData.dynamicContentTimeStamp;
    if (!iss) {
      return {
        name: 'Dynamic Content Freshness',
        passed: true,
        severity: 'info',
        message: 'Cannot compute freshness — no issuing detail',
      };
    }

    const validityDuration = ticket.security.validityDuration;
    if (validityDuration == null) {
      return {
        name: 'Dynamic Content Freshness',
        passed: true,
        severity: 'info',
        message: 'Cannot compute freshness — no validityDuration',
      };
    }

    // Compute generation timestamp from issuingYear + day + time
    const genTime = new Date(Date.UTC(iss.issuingYear, 0, ts.day, 0, 0, ts.time));
    const expiryTime = new Date(genTime.getTime() + validityDuration * 60 * 1000);
    const passed = now < expiryTime;

    return {
      name: 'Dynamic Content Freshness',
      passed,
      severity: 'warning',
      message: passed
        ? undefined
        : `Dynamic content expired at ${expiryTime.toISOString()}`,
    };
  }

  // Intercode dynamic data
  if (ticket.dynamicData) {
    const dd = ticket.dynamicData;
    if (!iss) {
      return {
        name: 'Dynamic Content Freshness',
        passed: true,
        severity: 'info',
        message: 'Cannot compute freshness — no issuing detail',
      };
    }

    // Compute issuing date
    const issuingDate = new Date(Date.UTC(iss.issuingYear, 0, iss.issuingDay));

    // Generation time = issuingDate + dynamicContentDay days + dynamicContentTime seconds + UTC offset
    const genTimeMs = issuingDate.getTime()
      + (dd.dynamicContentDay ?? 0) * 86400 * 1000
      + (dd.dynamicContentTime ?? 0) * 1000
      + (dd.dynamicContentUTCOffset ?? 0) * 15 * 60 * 1000;

    // Duration: dynamicContentDuration (seconds) or validityDuration (minutes)
    let durationMs: number | undefined;
    if (dd.dynamicContentDuration != null) {
      durationMs = dd.dynamicContentDuration * 1000;
    } else if (ticket.security.validityDuration != null) {
      durationMs = ticket.security.validityDuration * 60 * 1000;
    }

    if (durationMs == null) {
      return {
        name: 'Dynamic Content Freshness',
        passed: true,
        severity: 'info',
        message: 'Cannot compute freshness — no duration available',
      };
    }

    const expiryTime = new Date(genTimeMs + durationMs);
    const passed = now < expiryTime;

    return {
      name: 'Dynamic Content Freshness',
      passed,
      severity: 'warning',
      message: passed
        ? undefined
        : `Dynamic content expired at ${expiryTime.toISOString()}`,
    };
  }

  return {
    name: 'Dynamic Content Freshness',
    passed: true,
    severity: 'info',
    message: 'No dynamic content present',
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

  // Compute overall validity: all error-severity checks must pass
  const valid = Object.values(checks).every(
    c => c.severity !== 'error' || c.passed,
  );

  return { valid, ticket, checks };
}
