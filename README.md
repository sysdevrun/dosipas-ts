[![npm version](https://img.shields.io/npm/v/dosipas-ts)](https://www.npmjs.com/package/dosipas-ts)

# dosipas-ts

> **[Try the online playground](https://sysdevrun.github.io/dosipas-ts/)** — decode, encode, sign, verify, and control UIC barcode tickets in your browser.

Decode, encode, sign, verify, and control UIC barcode tickets with Intercode 6 extensions in TypeScript.

Handles the full UIC barcode envelope (header versions 1 and 2), FCB rail ticket data (versions 1, 2, and 3), Intercode 6 issuing extensions, dynamic data (both Intercode ID1 and FDC1 formats), and two-level ECDSA signature verification and signing.

ASN.1 PER unaligned payloads are parsed using [`asn1-per-ts`](https://github.com/sysdevrun/asn1-per-ts).

## Install

```bash
npm install dosipas-ts
```

## Requirements

- **Node.js >= 20** — Node 18 is not supported because `globalThis.crypto` (Web Crypto API) is not available as a stable global until Node 20. The `@noble/curves` and `@noble/hashes` dependencies rely on it for cryptographic operations.
- **ESM-only** — this package uses `"type": "module"` and provides only ESM exports.

## Decoding

```ts
import { decodeTicket, decodeTicketFromBytes } from 'dosipas-ts';

// From a hex string (whitespace and trailing 'h' are stripped)
const ticket = decodeTicket('815563dd8e76...');

// From raw bytes
const ticket = decodeTicketFromBytes(bytes);
```

The returned `UicBarcodeTicket` follows the UIC barcode ASN.1 schema hierarchy:

```ts
ticket.format                          // "U1" or "U2"
ticket.level2SignedData.level1Data     // security metadata + data sequence
ticket.level2SignedData.level1Signature // Level 1 signature bytes
ticket.level2SignedData.level2Data     // dynamic content block (FDC1 or Intercode ID1)
ticket.level2Signature                 // Level 2 signature bytes
```

Security metadata and algorithm OIDs live on `level1Data`:

```ts
const l1 = ticket.level2SignedData.level1Data;

l1.securityProviderNum   // RICS code of the security provider
l1.keyId                 // key ID for signature lookup
l1.level1KeyAlg          // Level 1 key algorithm OID
l1.level1SigningAlg      // Level 1 signing algorithm OID
l1.level2KeyAlg          // Level 2 key algorithm OID
l1.level2SigningAlg      // Level 2 signing algorithm OID
l1.level2PublicKey       // Level 2 public key bytes (embedded in barcode)
l1.endOfValidityYear     // v2 headers only
l1.endOfValidityDay      // v2 headers only
l1.validityDuration      // seconds
```

Rail ticket data is in `level1Data.dataSequence`:

```ts
const entry = ticket.level2SignedData.level1Data.dataSequence[0];

entry.dataFormat          // "FCB1", "FCB2", or "FCB3"
entry.data                // raw PER-encoded bytes

const rt = entry.decoded; // UicRailTicketData (when dataFormat is FCBn)
rt.issuingDetail?.issuerNum                // RICS code
rt.issuingDetail?.issuingYear              // e.g. 2025
rt.issuingDetail?.issuingDay               // day of year
rt.issuingDetail?.intercodeIssuing         // Intercode 6 issuing extension
rt.travelerDetail?.traveler?.[0].firstName // traveler name
rt.transportDocument?.[0].ticket           // { key: "openTicket", value: { ... } }
```

Dynamic content is in `level2Data`:

```ts
const l2 = ticket.level2SignedData.level2Data;

l2.dataFormat  // "FDC1" or "_3703.ID1" (Intercode)
l2.decoded     // UicDynamicContentData (FDC1) or IntercodeDynamicData (Intercode)
```

## Encoding

`encodeTicket` accepts the same `UicBarcodeTicket` type returned by `decodeTicket`, so round-tripping works directly:

```ts
import { decodeTicket, encodeTicket, encodeTicketToBytes } from 'dosipas-ts';
import type { UicBarcodeTicket } from 'dosipas-ts';

// Round-trip: decode → encode
const hex = encodeTicket(decodeTicket(originalHex));

// Build a ticket from scratch
const ticket: UicBarcodeTicket = {
  format: 'U2',
  level2SignedData: {
    level1Data: {
      securityProviderNum: 3703,
      keyId: 1,
      level1KeyAlg: '1.2.840.10045.3.1.7',
      level1SigningAlg: '1.2.840.10045.4.3.2',
      level2KeyAlg: '1.2.840.10045.3.1.7',
      level2SigningAlg: '1.2.840.10045.4.3.2',
      level2PublicKey: publicKeyBytes,
      dataSequence: [{
        dataFormat: 'FCB3',
        decoded: {
          issuingDetail: {
            issuerNum: 3703,
            issuingYear: 2025,
            issuingDay: 44,
            activated: true,
            specimen: false,
            securePaperTicket: false,
          },
          transportDocument: [
            { ticket: { key: 'openTicket', value: { returnIncluded: false } } },
          ],
        },
      }],
    },
    level1Signature: level1SigBytes,
    level2Data: {
      dataFormat: 'FDC1',
      decoded: { dynamicContentDay: 0, dynamicContentTime: 720 },
    },
  },
  level2Signature: level2SigBytes,
};

const encoded = encodeTicket(ticket);

// Or get bytes directly
const bytes = encodeTicketToBytes(ticket);
```

## Signing

Signing goes through the `Signer` interface — the signing-side counterpart of
`Level1KeyProvider`. A signer wraps wherever the private key actually lives:
`localSigner(privateKey, curve)` for a raw key in memory, or your own wrapper
over WebCrypto (non-extractable keys), an HSM or a cloud KMS:

```ts
interface Signer {
  curve: CurveName;                             // decides the OIDs and the hash
  sign(data: Uint8Array): Promise<Uint8Array>;  // DER-encoded ECDSA signature
  getPublicKey?(): Promise<Uint8Array>;         // required for Level 2 signers
}
```

Sign tickets with the two-level flow (Level 1, then Level 2):

```ts
import { signAndEncodeTicket, generateKeyPair, localSigner } from 'dosipas-ts';
import type { UicBarcodeTicket } from 'dosipas-ts';

const level1Key = generateKeyPair('P-256');
const level2Key = generateKeyPair('P-256');

const ticket: UicBarcodeTicket = {
  format: 'U2',
  level2SignedData: {
    level1Data: {
      securityProviderNum: 3703,
      keyId: 1,
      dataSequence: [{
        dataFormat: 'FCB3',
        decoded: {
          issuingDetail: {
            issuerNum: 3703,
            issuingYear: 2025,
            issuingDay: 44,
            activated: true,
            specimen: false,
            securePaperTicket: false,
          },
          transportDocument: [
            { ticket: { key: 'openTicket', value: { returnIncluded: false } } },
          ],
        },
      }],
    },
  },
};

const ticketBytes = await signAndEncodeTicket(ticket, {
  level1: localSigner(level1Key.privateKey, 'P-256'),
  level2: localSigner(level2Key.privateKey, 'P-256'), // omit for static barcodes
});
```

`signAndEncodeTicket` treats the signers as authoritative: the algorithm OIDs
(and the Level 2 public key) are written into the header from the signers,
whatever the input ticket carried, so its output is always self-consistent.

For finer control, sign each level independently. The low-level functions
sign the ticket's data **exactly as given** — an OID on the ticket that
contradicts the signer's curve is an error, and absent OIDs stay absent
(that is how barcodes whose algorithms are shared out of band are produced):

```ts
import { signLevel1, signLevel2, localSigner } from 'dosipas-ts';

const signer1 = localSigner(privateKey, 'P-256');
const signer2 = localSigner(level2PrivateKey, 'P-256');

const level1Sig = await signLevel1(ticket, signer1);
const level2Sig = await signLevel2(
  { ...ticket, level2SignedData: { ...ticket.level2SignedData, level1Signature: level1Sig } },
  signer2,
);
```

Key utilities: `generateKeyPair(curve)` makes a random key pair,
`derivePublicKey(privateKey, curve)` derives the uncompressed public point,
and `signPayload(data, privateKey, curve)` is the synchronous raw-key
signing primitive that `localSigner` wraps (used by the fully composable
flow below).

For a fully composable encoding flow using the low-level primitives (`encodeLevel1Data`, `encodeLevel2SignedData`, `encodeUicBarcode`), see [`examples/encoder.ts`](examples/encoder.ts).

## Signature verification

UIC barcodes use a two-level signature scheme:

- **Level 2** is self-contained: the public key is embedded in the barcode.
- **Level 1** requires an external public key from the UIC public key registry.

### Verify Level 2 only (no external key needed)

```ts
import { verifyLevel2Signature } from 'dosipas-ts';

const result = await verifyLevel2Signature(barcodeBytes);
// { valid: true, algorithm: 'ECDSA P-256 with SHA-256' }
```

### Verify both levels

```ts
import { verifySignatures } from 'dosipas-ts';

const result = await verifySignatures(barcodeBytes, {
  level1Key: { publicKey: publicKeyBytes },
});
// { level1: { valid: true, ... }, level2: { valid: true, ... } }
```

### Using a key provider

```ts
import { verifySignatures, findKeyInXml } from 'dosipas-ts';
import type { Level1KeyProvider } from 'dosipas-ts';

// Parse the UIC public key XML (from https://railpublickey.uic.org)
const xml = fs.readFileSync('uic-publickeys.xml', 'utf-8');

const provider: Level1KeyProvider = {
  async getPublicKey(key) {
    // `key` is a SignatureKey: issuer + keyId as extracted from the barcode.
    // Note: key.securityProviderNum is undefined for issuers that identify
    // themselves with an IA5 string instead of a numeric RICS code — those
    // are not in the UIC registry, so branch on key.securityProviderIA5.
    const material = findKeyInXml(xml, key); // null for IA5 issuers
    if (!material) throw new Error(`Key not found: ${key.id}`);
    return material;
  },
};

const result = await verifySignatures(barcodeBytes, {
  level1KeyProvider: provider,
});
```

`findKeyInXml` returns `{ publicKey }` only. The registry's `signatureAlgorithm`
element is free-form vendor text (`'SHA1withDSA(1024,160)'`, `'DSA1024'`, ...)
and never records a curve, so it is surfaced unparsed on `parseKeysXml` entries
and never used for verification.

### Verify Level 1 directly

```ts
import { verifyLevel1Signature } from 'dosipas-ts';

const result = await verifyLevel1Signature(barcodeBytes, { publicKey: publicKeyBytes });
```

### Barcodes that omit their algorithm OIDs

Some issuers leave `level1KeyAlg` / `level1SigningAlg` out of the header and
share the algorithm out of band. Supply the OIDs alongside the key:

```ts
import { verifyLevel1Signature, CAR_JAUNE_TICKET_HEX } from 'dosipas-ts';

const result = await verifyLevel1Signature(barcodeBytes, {
  publicKey,
  keyAlg: '1.2.840.10045.3.1.7',     // P-256
  signingAlg: '1.2.840.10045.4.3.2', // ECDSA with SHA-256
});
// { valid: true, algorithm: 'ECDSA P-256 with SHA-256', algorithmSource: 'configured' }
```

Level 2 works the same way — its public key is embedded in the barcode, but its
OIDs can be absent too:

```ts
await verifySignatures(barcodeBytes, {
  level1Key: { publicKey, keyAlg: '...', signingAlg: '...' },
  level2Algorithms: { keyAlg: '...', signingAlg: '...' },
});
```

These fields take **dotted-decimal OIDs only** — names such as `'P-256'` or
`'SHA256withECDSA'` are rejected. The accepted values are the keys of
`SIGNING_ALGORITHMS` and `KEY_ALGORITHMS`, both exported from the package.

Precedence is strict, and nothing is ever inferred from the key material:

1. the OID carried in the barcode, when present;
2. otherwise the OID you supply here;
3. otherwise verification fails with an explanatory error.

If the barcode and your configuration **disagree**, verification fails with a
mismatch error rather than silently preferring one. The barcode's OIDs sit
inside the signed data, so a disagreement means either the trust store is
misconfigured or the credential is not what you think it is.

## Recovering a Level 1 public key from tickets

When an issuer's key is published nowhere (e.g. the issuer identifies itself
with an IA5 string, so it cannot be in the UIC registry), the key can be
*recovered* from observed tickets. Each ECDSA signature yields two candidate
keys; the true key is a candidate for every ticket of the batch, so the
intersection across two or more tickets is unique in practice:

```ts
import { recoverLevel1PublicKey } from 'dosipas-ts';

const candidates = recoverLevel1PublicKey([ticketBytes1, ticketBytes2]);
// [Uint8Array] — one uncompressed EC point (0x04 || x || y)

// Extracted tickets are accepted too — e.g. a signature group's tickets:
const candidates2 = recoverLevel1PublicKey(group.tickets);
```

With a single ticket, expect two candidates (either verifies that ticket —
collect a second ticket to disambiguate). An empty result means the tickets
were not all signed with the same key. For barcodes that omit their algorithm
OIDs, supply them like for verification:

```ts
const candidates = recoverLevel1PublicKey([ticketBytes], {
  keyAlg: '1.2.840.10045.3.1.7',     // P-256
  signingAlg: '1.2.840.10045.4.3.2', // ECDSA with SHA-256
});
```

This is how the built-in Car Jaune fixture key was obtained. Recovering a
public key discloses no secret — it computes something any verifier of the
batch could compute. Only ECDSA is supported (not DSA/RSA).

## Ticket control

Perform comprehensive validation of a ticket in a single call:

```ts
import { controlTicket } from 'dosipas-ts';

// Accepts a hex string or raw bytes
const result = await controlTicket(payload, {
  level1KeyProvider: provider,
  expectedIntercodeNetworkIds: new Set(['250502']),
});

result.valid   // true only if all error-severity checks passed
result.ticket  // decoded UicBarcodeTicket
result.checks  // individual check results keyed by name
```

`ControlOptions` extends `VerifyOptions`, so `level1Key` and `level2Algorithms`
are accepted here too. Signature checks also report `algorithm` and
`algorithmSource` (`'barcode' | 'configured' | 'mixed'`), so you can see which
algorithm verified a ticket and where it came from.

Checks performed: decode, header format, security info, Level 1 signature, Level 2 signature, expiry, specimen flag, activated flag, issuing detail, transport document, Intercode extension (with optional network ID validation), dynamic data format, dynamic content freshness, zones & carriers, and open ticket validity.

## Time helpers

Compute UTC timestamps from ticket fields:

```ts
import { getIssuingTime, getEndOfValidityTime, getDynamicContentTime } from 'dosipas-ts';

const ticket = decodeTicket(hex);

getIssuingTime(ticket)         // Date from issuingYear + issuingDay + issuingTime
getEndOfValidityTime(ticket)   // Date from v2 endOfValidity fields or v1 issuing + duration
getDynamicContentTime(ticket)  // Date from FDC1 timestamp or Intercode ID1 dynamic fields
```

For open tickets, `getOpenTicketValidityWindow(openTicket, issuingDetail)`
computes the `{ validFrom, validUntil }` window from the relative
day/time/UTC-offset fields.

## Extracting signatures and signed data

`extractTicket` produces the canonical `ExtractedTicket` record: the exact
signed bytes, the signatures, the algorithm OIDs and the Level 1 key identity,
structured per level:

```ts
import { extractTicket } from 'dosipas-ts';

const ticket = extractTicket(barcodeBytes);

ticket.key                // SignatureKey: issuer + keyId
ticket.key.id             // canonical label, e.g. "1187/1" or "IWN8/1"
ticket.level1.signedBytes // exact bytes covered by the Level 1 signature
ticket.level1.signature   // Level 1 signature (DER), if present
ticket.level1.keyAlg      // key algorithm OID, if the barcode carries one
ticket.level1.signingAlg  // signing algorithm OID, if the barcode carries one
ticket.level2             // same shape, plus the embedded level2 publicKey
```

`verifySignatures`, `verifyLevel1Signature`, `verifyLevel2Signature`,
`recoverLevel1PublicKey` and `SignatureCollector.add` all accept an
`ExtractedTicket` in place of raw payload bytes, so a scan pipeline decodes
each payload exactly once.

## Collecting signatures from many scans

When scanning many QR codes (e.g. with a camera in a control app), feed each
scanned payload to a `SignatureCollector`: tickets are extracted and
classified automatically by Level 1 key identity (`SignatureKey`), and rescans
of the same barcode are deduplicated byte-for-byte. Unreadable scans are
expected input in a camera loop, so `add` reports them as a result instead of
throwing:

```ts
import { SignatureCollector, signatureKey } from 'dosipas-ts';

const collector = new SignatureCollector();

for (const payload of scans) {
  const result = collector.add(payload); // Uint8Array or ExtractedTicket
  switch (result.status) {
    case 'added':     console.log(`new ticket for key ${result.group.key.id}`); break;
    case 'duplicate': break; // same barcode scanned again — nothing changed
    case 'invalid':   break; // not a decodable UIC barcode — nothing changed
  }
}

for (const group of collector.groups()) {
  group.key     // SignatureKey — securityProviderNum/IA5, keyId, id label
  group.tickets // ExtractedTicket[] — full records, in scan order
}

collector.group('3703/7') // lookup by id label...
collector.group(signatureKey({ securityProviderIA5: 'IWN8', keyId: 1 })) // ...or by key
```

For a batch already in hand, `collectSignatures(payloads)` does the same in
one call (and throws on an undecodable payload, naming its index). Each group
plugs directly into the rest of the library: look its key up in the UIC
registry with `findKeyInXml(xml, group.key)`, recover it from the observed
tickets with `recoverLevel1PublicKey(group.tickets)`, or verify without
re-decoding with `verifySignatures(ticket, options)`.

## UIC public key XML utilities

```ts
import { findKeyInXml, parseKeysXml } from 'dosipas-ts';

// Find a specific key — by issuer RICS code + keyId, or by a SignatureKey
// (from an extracted ticket or a signature group)
const key = findKeyInXml(xml, 1187, 1);
const key2 = findKeyInXml(xml, extractTicket(bytes).key);
// Returns { publicKey: Uint8Array } or null — no algorithm metadata,
// see the note under "Using a key provider" above. A SignatureKey whose
// issuer is an IA5 string yields null (the registry is keyed by RICS codes).

// Parse all keys
const keys = parseKeysXml(xml);
// [{ issuerCode, id, issuerName, publicKey, signatureAlgorithm, ... }]
```

Entries whose base64 public key is malformed are skipped by `parseKeysXml`
rather than failing the whole parse; `findKeyInXml` throws for such an entry so
a corrupt key is never mistaken for a missing one. Entries with a non-numeric
`<id>` are not returned.

## Built-in fixtures

The package exports hex-encoded sample tickets for testing:

```ts
import {
  SAMPLE_TICKET_HEX,
  SNCF_TER_TICKET_HEX,
  SOLEA_TICKET_HEX,
  CTS_TICKET_HEX,
  GRAND_EST_U1_FCB3_HEX,
  BUS_ARDECHE_TICKET_HEX,
  BUS_AIN_TICKET_HEX,
  DROME_BUS_TICKET_HEX,
  CAR_JAUNE_TICKET_HEX,
} from 'dosipas-ts';
```

And signature fixture data:

```ts
import { SNCF_TER_SIGNATURES, SOLEA_SIGNATURES, CTS_SIGNATURES, CAR_JAUNE_SIGNATURES } from 'dosipas-ts';
```

## Supported algorithms

| Algorithm | Signing | Verification |
|-----------|---------|--------------|
| ECDSA P-256 with SHA-256 | Yes | Yes |
| ECDSA P-384 with SHA-384 | Yes | Yes |
| ECDSA P-521 with SHA-512 | Yes | Yes |
| DSA with SHA-224/256 | No | Detected only |
| RSA with SHA-256 | No | Detected only |

The OIDs for these live in `SIGNING_ALGORITHMS` and `KEY_ALGORITHMS`
(`src/oids.ts`), exported from the package, with `getSigningAlgorithm(oid)` /
`getKeyAlgorithm(oid)` for single lookups. Those tables are the accepted
values for the `keyAlg` / `signingAlg` fields described above; note that the
DSA and RSA entries are recognised for reporting but never verify.

## License

MIT
