#!/usr/bin/env npx tsx
/**
 * CLI tool to decode and verify UIC barcode tickets.
 *
 * Usage:
 *   npx tsx cli/decode-ticket.ts <hex-file-or-inline-hex> [options]
 *   npx tsx cli/decode-ticket.ts solea                     # built-in fixture
 *   npx tsx cli/decode-ticket.ts path/to/ticket.hex        # hex file
 *   npx tsx cli/decode-ticket.ts "815563dd8e76..."         # inline hex
 *   npx tsx cli/decode-ticket.ts solea --keys keys.xml     # custom Level 1 keys
 *   npx tsx cli/decode-ticket.ts solea --no-keys           # skip Level 1 verification
 *
 * Level 1 verification uses tests/fixtures/uic-publickeys.xml by default.
 *
 * Built-in fixtures: sample, sncf, solea, cts, grand_est, ardeche, ain, drome, car_jaune
 */

import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import {
  decodeTicket,
  verifyLevel2Signature,
  verifyLevel1Signature,
  extractSignedData,
  findKeyInXml,
  getIssuingTime,
  getEndOfValidityTime,
  getDynamicContentTime,
  SAMPLE_TICKET_HEX,
  SNCF_TER_TICKET_HEX,
  SOLEA_TICKET_HEX,
  CTS_TICKET_HEX,
  GRAND_EST_U1_FCB3_HEX,
  BUS_ARDECHE_TICKET_HEX,
  BUS_AIN_TICKET_HEX,
  DROME_BUS_TICKET_HEX,
  CAR_JAUNE_TICKET_HEX,
} from '../src/index';
import { getSigningAlgorithm, getKeyAlgorithm } from '../src/oids';
import type {
  UicBarcodeTicket,
  Level1Data,
  UicRailTicketData,
  IntercodeDynamicData,
  UicDynamicContentData,
} from '../src/types';

// ---------------------------------------------------------------------------
// Named fixtures
// ---------------------------------------------------------------------------

const FIXTURES: Record<string, string> = {
  sample: SAMPLE_TICKET_HEX,
  sncf: SNCF_TER_TICKET_HEX,
  sncf_ter: SNCF_TER_TICKET_HEX,
  solea: SOLEA_TICKET_HEX,
  cts: CTS_TICKET_HEX,
  grand_est: GRAND_EST_U1_FCB3_HEX,
  ardeche: BUS_ARDECHE_TICKET_HEX,
  ain: BUS_AIN_TICKET_HEX,
  drome: DROME_BUS_TICKET_HEX,
  car_jaune: CAR_JAUNE_TICKET_HEX,
};

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const CYAN = '\x1b[36m';
const DIM = '\x1b[2m';
const BOLD = '\x1b[1m';
const RESET = '\x1b[0m';

function ok(msg: string) { console.log(`  ${GREEN}✓${RESET} ${msg}`); }
function fail(msg: string) { console.log(`  ${RED}✗${RESET} ${msg}`); }
function warn(msg: string) { console.log(`  ${YELLOW}⚠${RESET} ${msg}`); }
function heading(msg: string) { console.log(`\n${BOLD}${CYAN}${msg}${RESET}`); }

function field(label: string, value: unknown, indent = 2) {
  if (value === undefined || value === null) return;
  const pad = ' '.repeat(indent);
  console.log(`${pad}${DIM}${label}:${RESET} ${value}`);
}

function bytesField(label: string, bytes: Uint8Array | undefined, indent = 2) {
  if (!bytes) return;
  const pad = ' '.repeat(indent);
  const hex = toHex(bytes);
  const display = hex.length > 64 ? hex.substring(0, 64) + '...' : hex;
  console.log(`${pad}${DIM}${label}:${RESET} [${bytes.length} bytes] ${display}`);
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/[\s\n\r]/g, '');
  return new Uint8Array(clean.match(/.{1,2}/g)!.map(b => parseInt(b, 16)));
}

function formatDate(year: number, day: number): string {
  const d = new Date(year, 0, day);
  return d.toLocaleDateString('en-GB', { year: 'numeric', month: 'short', day: 'numeric' });
}

function formatTime(minutes: number): string {
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  return `${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}`;
}

function algName(oid: string | undefined, type: 'signing' | 'key'): string {
  if (!oid) return '';
  if (type === 'signing') {
    const alg = getSigningAlgorithm(oid);
    return alg ? ` (${alg.type} ${alg.hash})` : '';
  }
  const alg = getKeyAlgorithm(oid);
  return alg ? ` (${alg.type}${alg.curve ? ' ' + alg.curve : ''})` : '';
}

// ---------------------------------------------------------------------------
// Display functions
// ---------------------------------------------------------------------------

function printSecurity(l1: Level1Data) {
  heading('Security');
  field('Security provider', l1.securityProviderNum);
  if (l1.securityProviderIA5) field('Security provider (IA5)', l1.securityProviderIA5);
  field('Key ID', l1.keyId);
  if (l1.level1KeyAlg) field('Level 1 key algorithm', l1.level1KeyAlg + algName(l1.level1KeyAlg, 'key'));
  if (l1.level2KeyAlg) field('Level 2 key algorithm', l1.level2KeyAlg + algName(l1.level2KeyAlg, 'key'));
  if (l1.level1SigningAlg) field('Level 1 signing algorithm', l1.level1SigningAlg + algName(l1.level1SigningAlg, 'signing'));
  if (l1.level2SigningAlg) field('Level 2 signing algorithm', l1.level2SigningAlg + algName(l1.level2SigningAlg, 'signing'));
  bytesField('Level 2 public key', l1.level2PublicKey);
  bytesField('Level 1 signature', ticket?.level2SignedData.level1Signature);
  if (l1.endOfValidityYear != null) {
    field('End of validity', formatDate(l1.endOfValidityYear, l1.endOfValidityDay ?? 1));
  }
  if (l1.endOfValidityTime != null) field('End of validity time', formatTime(l1.endOfValidityTime));
  if (l1.validityDuration != null) field('Validity duration', `${l1.validityDuration} sec`);
}

function printRailTicket(rt: UicRailTicketData, dataFormat: string) {
  const fcbVersion = dataFormat.replace('FCB', '');
  heading(`Rail Ticket (FCB${fcbVersion})`);

  if (rt.issuingDetail) {
    const iss = rt.issuingDetail;
    console.log(`  ${BOLD}Issuing Detail${RESET}`);
    field('Security provider', iss.securityProviderNum, 4);
    if (iss.securityProviderIA5) field('Security provider (IA5)', iss.securityProviderIA5, 4);
    field('Issuer', iss.issuerNum, 4);
    if (iss.issuerIA5) field('Issuer (IA5)', iss.issuerIA5, 4);
    if (iss.issuingYear && iss.issuingDay) {
      field('Issuing date', formatDate(iss.issuingYear, iss.issuingDay), 4);
    }
    field('Issuing year', iss.issuingYear, 4);
    field('Issuing day', iss.issuingDay, 4);
    if (iss.issuingTime != null) field('Issuing time', formatTime(iss.issuingTime), 4);
    if (iss.issuerName) field('Issuer name', iss.issuerName, 4);
    field('Specimen', iss.specimen ? 'Yes' : 'No', 4);
    field('Activated', iss.activated ? 'Yes' : 'No', 4);
    if (iss.currency) field('Currency', iss.currency, 4);
    if (iss.currencyFract != null) field('Currency fract', iss.currencyFract, 4);
    if (iss.issuerPNR) field('Issuer PNR', iss.issuerPNR, 4);

    if (iss.intercodeIssuing) {
      console.log(`    ${BOLD}Intercode 6 Issuing Extension (_<RICS>II1)${RESET}`);
      field('Intercode version', iss.intercodeIssuing.intercodeVersion, 6);
      field('Intercode instanciation', iss.intercodeIssuing.intercodeInstanciation, 6);
      bytesField('Network ID', iss.intercodeIssuing.networkId, 6);
      if (iss.intercodeIssuing.productRetailer) {
        const pr = iss.intercodeIssuing.productRetailer;
        if (pr.retailChannel) field('Retail channel', pr.retailChannel, 6);
        if (pr.retailGeneratorId != null) field('Retail generator ID', pr.retailGeneratorId, 6);
        if (pr.retailServerId != null) field('Retail server ID', pr.retailServerId, 6);
        if (pr.retailerId != null) field('Retailer ID', pr.retailerId, 6);
        if (pr.retailPointId != null) field('Retail point ID', pr.retailPointId, 6);
      }
    }

    if (iss.extension) {
      console.log(`    ${BOLD}Extension${RESET}`);
      field('Extension ID', iss.extension.extensionId, 6);
      bytesField('Extension data', iss.extension.extensionData, 6);
    }
  }

  if (rt.travelerDetail) {
    const td = rt.travelerDetail;
    console.log(`  ${BOLD}Traveler Detail${RESET}`);
    if (td.preferredLanguage) field('Preferred language', td.preferredLanguage, 4);
    if (td.groupName) field('Group name', td.groupName, 4);
    if (td.traveler && td.traveler.length > 0) {
      for (let i = 0; i < td.traveler.length; i++) {
        const t = td.traveler[i];
        const name = [t.firstName, t.secondName, t.lastName].filter(Boolean).join(' ');
        console.log(`    ${BOLD}Traveler ${i + 1}${RESET}`);
        if (name) field('Name', name, 6);
        if (t.dateOfBirth) field('Date of birth', t.dateOfBirth, 6);
        if (t.yearOfBirth) field('Year of birth', t.yearOfBirth, 6);
        if (t.gender) field('Gender', t.gender, 6);
        if (t.ticketHolder != null) field('Ticket holder', t.ticketHolder ? 'Yes' : 'No', 6);
        if (t.passengerType) field('Passenger type', t.passengerType, 6);
        if (t.customerIdIA5) field('Customer ID (IA5)', t.customerIdIA5, 6);
        if (t.customerIdNum != null) field('Customer ID (num)', t.customerIdNum, 6);
        if (t.countryOfResidence) field('Country of residence', t.countryOfResidence, 6);
        if (t.status && t.status.length > 0) {
          for (const s of t.status) {
            field('Status', `${s.customerStatusDescr ?? s.customerStatus ?? '?'} (provider ${s.statusProviderNum ?? s.statusProviderIA5 ?? '?'})`, 6);
          }
        }
      }
    }
  }

  if (rt.transportDocument && rt.transportDocument.length > 0) {
    console.log(`  ${BOLD}Transport Documents (${rt.transportDocument.length})${RESET}`);
    for (let i = 0; i < rt.transportDocument.length; i++) {
      const doc = rt.transportDocument[i];
      console.log(`    ${BOLD}Document ${i + 1}: ${doc.ticket.key}${RESET}`);
      printObject(doc.ticket.value as Record<string, unknown>, 6);
    }
  }

  if (rt.controlDetail) {
    console.log(`  ${BOLD}Control Detail${RESET}`);
    const cd = rt.controlDetail;
    if (cd.identificationByIdCard != null) field('ID card required', cd.identificationByIdCard ? 'Yes' : 'No', 4);
    if (cd.identificationByPassportId != null) field('Passport required', cd.identificationByPassportId ? 'Yes' : 'No', 4);
    if (cd.onlineValidationRequired != null) field('Online validation', cd.onlineValidationRequired ? 'Yes' : 'No', 4);
    if (cd.ageCheckRequired != null) field('Age check', cd.ageCheckRequired ? 'Yes' : 'No', 4);
    if (cd.infoText) field('Info text', cd.infoText, 4);
    if (cd.identificationByCardReference && cd.identificationByCardReference.length > 0) {
      for (const cr of cd.identificationByCardReference) {
        field('Card reference', cr.cardName ?? cr.cardIdIA5 ?? cr.cardIdNum ?? '?', 4);
      }
    }
    if (cd.includedTickets && cd.includedTickets.length > 0) {
      for (const tl of cd.includedTickets) {
        field('Linked ticket', `${tl.ticketType ?? '?'} (${tl.issuerName ?? tl.productOwnerNum ?? '?'})`, 4);
      }
    }
    if (cd.extension) {
      field('Extension ID', cd.extension.extensionId, 4);
      bytesField('Extension data', cd.extension.extensionData, 4);
    }
  }
}

function printObject(obj: Record<string, unknown>, indent: number) {
  const pad = ' '.repeat(indent);
  for (const [key, val] of Object.entries(obj)) {
    if (val === undefined || val === null) continue;
    if (val instanceof Uint8Array) {
      bytesField(key, val, indent);
    } else if (typeof val === 'object' && !Array.isArray(val)) {
      console.log(`${pad}${DIM}${key}:${RESET}`);
      printObject(val as Record<string, unknown>, indent + 2);
    } else if (Array.isArray(val)) {
      console.log(`${pad}${DIM}${key}:${RESET} [${val.length} items]`);
      for (let i = 0; i < val.length; i++) {
        const item = val[i];
        if (typeof item === 'object' && item !== null && !(item instanceof Uint8Array)) {
          console.log(`${pad}  ${DIM}[${i}]${RESET}`);
          printObject(item as Record<string, unknown>, indent + 4);
        } else {
          console.log(`${pad}  ${DIM}[${i}]:${RESET} ${item}`);
        }
      }
    } else {
      field(key, val, indent);
    }
  }
}

function printDynamicData(ticket: UicBarcodeTicket) {
  const l2 = ticket.level2SignedData.level2Data;
  if (!l2) return;

  heading('Level 2 Data Block');
  field('Data format', l2.dataFormat);
  bytesField('Raw data', l2.data);

  const match = l2.dataFormat.match(/^_(\d+)\.ID1$/);
  if (match) {
    field('Type', `Intercode 6 Dynamic Data (_<RICS>.ID1, RICS=${match[1]})`);
  }

  if (l2.decoded) {
    if (/^_\d+\.ID1$/.test(l2.dataFormat)) {
      const dd = l2.decoded as IntercodeDynamicData;
      console.log(`  ${BOLD}Intercode 6 Dynamic Data (decoded)${RESET}`);
      field('Dynamic content day', dd.dynamicContentDay, 4);
      if (dd.dynamicContentTime != null)
        field('Dynamic content time', dd.dynamicContentTime, 4);
      if (dd.dynamicContentUTCOffset != null)
        field('UTC offset', dd.dynamicContentUTCOffset, 4);
      if (dd.dynamicContentDuration != null)
        field('Duration', `${dd.dynamicContentDuration} min`, 4);
    } else if (l2.dataFormat === 'FDC1') {
      const fdc = l2.decoded as UicDynamicContentData;
      console.log(`  ${BOLD}UIC Dynamic Content (decoded)${RESET}`);
      if (fdc.dynamicContentMobileAppId) field('Mobile app ID', fdc.dynamicContentMobileAppId, 4);
      if (fdc.dynamicContentTimeStamp) {
        field('Timestamp day', fdc.dynamicContentTimeStamp.day, 4);
        field('Timestamp time', fdc.dynamicContentTimeStamp.time, 4);
      }
    }
  }
}

function printTimestamps(ticket: UicBarcodeTicket) {
  heading('Timestamps');
  const issuing = getIssuingTime(ticket);
  const endOfValidity = getEndOfValidityTime(ticket);
  const dynamicContent = getDynamicContentTime(ticket);

  if (issuing) field('Issuing time (UTC)', issuing.toISOString());
  if (endOfValidity) field('End of validity (UTC)', endOfValidity.toISOString());
  if (dynamicContent) field('Dynamic content time (UTC)', dynamicContent.toISOString());
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

let ticket: UicBarcodeTicket | undefined;

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args[0] === '--help' || args[0] === '-h') {
    console.log(`Usage: npx tsx cli/decode-ticket.ts <input> [--keys path/to/keys.xml]`);
    console.log();
    console.log('Input can be:');
    console.log('  A fixture name: sample, sncf, solea, cts, grand_est, ardeche, ain, drome, car_jaune');
    console.log('  A path to a .hex file');
    console.log('  Inline hex data');
    console.log();
    console.log('Options:');
    console.log('  --keys <path>          UIC public key XML file for Level 1 verification');
    console.log('                         (default: tests/fixtures/uic-publickeys.xml)');
    console.log('  --no-keys              Skip Level 1 signature verification');
    console.log('  --l1-key-alg <oid>     Level 1 key algorithm OID, for barcodes that omit it');
    console.log('                         (e.g. 1.2.840.10045.3.1.7 for P-256)');
    console.log('  --l1-signing-alg <oid> Level 1 signing algorithm OID, for barcodes that omit it');
    console.log('                         (e.g. 1.2.840.10045.4.3.2 for ECDSA with SHA-256)');
    process.exit(0);
  }

  /** Pull `--flag <value>` out of args, returning the value if present. */
  function takeOption(name: string): string | undefined {
    const idx = args.indexOf(name);
    if (idx === -1) return undefined;
    const value = args[idx + 1];
    if (!value) {
      console.error(`Error: ${name} requires a value`);
      process.exit(1);
    }
    args.splice(idx, 2);
    return value;
  }

  const l1KeyAlg = takeOption('--l1-key-alg');
  const l1SigningAlg = takeOption('--l1-signing-alg');

  // Parse --keys option (defaults to bundled UIC public keys)
  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const defaultKeysPath = path.join(__dirname, '..', 'tests', 'fixtures', 'uic-publickeys.xml');

  let keysXml: string | undefined;
  const noKeysIdx = args.indexOf('--no-keys');
  if (noKeysIdx !== -1) {
    args.splice(noKeysIdx, 1);
  } else {
    const keysIdx = args.indexOf('--keys');
    let keysPath: string;
    if (keysIdx !== -1) {
      keysPath = args[keysIdx + 1];
      if (!keysPath) {
        console.error('Error: --keys requires a path to the XML key file');
        process.exit(1);
      }
      args.splice(keysIdx, 2);
    } else {
      keysPath = defaultKeysPath;
    }
    if (fs.existsSync(keysPath)) {
      keysXml = fs.readFileSync(keysPath, 'utf-8');
    }
  }

  // Resolve hex input
  let hex: string;
  const input = args[0];

  if (FIXTURES[input.toLowerCase()]) {
    hex = FIXTURES[input.toLowerCase()];
    console.log(`Using ${BOLD}${input.toLowerCase()}${RESET} fixture`);
  } else if (fs.existsSync(input)) {
    hex = fs.readFileSync(input, 'utf-8').trim();
    console.log(`Reading from ${BOLD}${input}${RESET}`);
  } else if (/^[0-9a-fA-F\s]+h?$/.test(input.trim())) {
    hex = input;
    console.log(`Using inline hex (${input.length} chars)`);
  } else {
    console.error(`Unknown input: ${input}`);
    console.error('Use a fixture name (sample, sncf, solea, cts, grand_est, ardeche, ain, drome, car_jaune), a .hex file, or inline hex.');
    process.exit(1);
  }

  // Decode
  heading('Decoding ticket...');
  try {
    ticket = decodeTicket(hex);
    ok('Ticket decoded successfully');
  } catch (e: unknown) {
    fail(`Decoding failed: ${e instanceof Error ? e.message : 'unknown error'}`);
    process.exit(1);
  }

  const l1 = ticket.level2SignedData.level1Data;

  // Header
  heading('Header');
  field('Format', ticket.format);
  bytesField('Level 2 signature', ticket.level2Signature);

  // Security
  printSecurity(l1);

  // Rail tickets
  for (const entry of l1.dataSequence) {
    if (entry.decoded) {
      printRailTicket(entry.decoded, entry.dataFormat);
    } else {
      heading(`Data Block (${entry.dataFormat})`);
      bytesField('Data', entry.data);
    }
  }

  // Level 2 data / dynamic data
  printDynamicData(ticket);

  // Computed timestamps
  printTimestamps(ticket);

  // Signature verification
  heading('Signature Verification');

  const bytes = hexToBytes(hex);

  // Level 2
  const l2Result = await verifyLevel2Signature(bytes);
  if (l2Result.valid) {
    ok(`Level 2: ${GREEN}VALID${RESET} (${l2Result.algorithm})`);
  } else if (l2Result.error?.includes('Missing')) {
    warn(`Level 2: ${YELLOW}NOT PRESENT${RESET} (${l2Result.error})`);
  } else {
    fail(`Level 2: ${RED}INVALID${RESET} (${l2Result.error})`);
  }

  // Level 1
  if (keysXml) {
    const extracted = extractSignedData(bytes);
    const { security } = extracted;
    const issuerCode = security.securityProviderNum;
    const keyId = security.keyId;

    if (issuerCode != null && keyId != null) {
      const registryKey = findKeyInXml(keysXml, issuerCode, keyId);
      if (registryKey) {
        ok(
          `Found Level 1 key for issuer ${issuerCode}, key ID ${keyId} ` +
            `[${registryKey.publicKey.length} bytes]`,
        );
        // The registry carries no usable algorithm metadata, so OIDs the
        // barcode omits have to come from the command line.
        const l1Result = await verifyLevel1Signature(bytes, {
          ...registryKey,
          keyAlg: l1KeyAlg,
          signingAlg: l1SigningAlg,
        });
        if (l1Result.valid) {
          ok(`Level 1: ${GREEN}VALID${RESET} (${l1Result.algorithm})`);
        } else if (l1Result.error?.includes('Missing')) {
          warn(`Level 1: ${YELLOW}NOT VERIFIABLE${RESET} (${l1Result.error})`);
        } else {
          fail(`Level 1: ${RED}INVALID${RESET} (${l1Result.error})`);
        }
      } else {
        warn(`No Level 1 key found in XML for issuer ${issuerCode}, key ID ${keyId}`);
      }
    } else {
      warn('Cannot look up Level 1 key: missing issuer code or key ID');
    }
  } else {
    warn('Level 1 verification skipped (no keys file found)');
  }

  console.log();
}

main().catch((e) => {
  console.error(`Fatal error: ${e instanceof Error ? e.message : e}`);
  process.exit(1);
});
