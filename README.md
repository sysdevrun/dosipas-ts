# dosipas-ts

> **[Try the online playground](https://theophile.github.io/dosipas-ts/)** — decode, encode, sign, and verify UIC barcode tickets in your browser.

Decode, encode, and verify UIC barcode tickets with Intercode 6 extensions in TypeScript.

Handles the full UIC barcode envelope (header versions 1 and 2), FCB rail ticket data (versions 1, 2, and 3), Intercode 6 issuing extensions, dynamic data, and two-level ECDSA signature verification.

## Install

```bash
npm install dosipas-ts
```

Requires Node.js 18+. ESM-only.

## Decoding

```ts
import { decodeTicket, decodeTicketFromBytes } from 'dosipas-ts';

// From a hex string (whitespace and trailing 'h' are stripped)
const ticket = decodeTicket('815563dd8e76...');

// From raw bytes
const ticket = decodeTicketFromBytes(bytes);
```

The returned `UicBarcodeTicket` object contains:

```ts
ticket.format          // "U1" or "U2"
ticket.headerVersion   // 1 or 2
ticket.security        // SecurityInfo (provider, key IDs, algorithms, signatures)
ticket.railTickets     // RailTicketData[] (FCB-decoded ticket data)
ticket.otherDataBlocks // DataBlock[] (non-FCB data blocks)
ticket.dynamicData     // IntercodeDynamicData (Intercode 6 Level 2, if present)
ticket.level2Signature // Uint8Array (if present)
```

Each rail ticket includes typed fields for issuing details, traveler info, transport documents, and control details:

```ts
const rt = ticket.railTickets[0];

rt.fcbVersion                              // 1, 2, or 3
rt.issuingDetail?.issuerNum                // RICS code
rt.issuingDetail?.issuingYear              // e.g. 2025
rt.issuingDetail?.issuingDay               // day of year
rt.issuingDetail?.intercodeIssuing         // Intercode 6 issuing extension
rt.travelerDetail?.traveler?.[0].firstName // traveler name
rt.transportDocument?.[0].ticketType       // e.g. "openTicket", "reservation"
rt.raw                                     // full decoded object for fields not covered above
```

## Encoding

```ts
import { encodeTicket, encodeTicketToBytes } from 'dosipas-ts';

const hex = encodeTicket({
  headerVersion: 2,
  fcbVersion: 2,
  securityProviderNum: 3703,
  keyId: 1,
  level1KeyAlg: '1.2.840.10045.3.1.7',
  level2KeyAlg: '1.2.840.10045.3.1.7',
  level1SigningAlg: '1.2.840.10045.4.3.2',
  level2SigningAlg: '1.2.840.10045.4.3.2',
  level2PublicKey: publicKeyBytes,
  level1Signature: level1SigBytes,
  level2Signature: level2SigBytes,
  railTicket: {
    issuingDetail: {
      securityProviderNum: 3703,
      issuerNum: 3703,
      issuingYear: 2025,
      issuingDay: 44,
      activated: true,
      currency: 'EUR',
      currencyFract: 2,
      intercodeIssuing: {
        networkId: new Uint8Array([0x11, 0x87]),
        productRetailer: { retailChannel: 'mobileApplication' },
      },
    },
    transportDocument: [
      { ticketType: 'openTicket', ticket: { /* ... */ } },
    ],
  },
  dynamicData: {
    rics: 3703,
    dynamicContentDay: 0,
    dynamicContentTime: 720,
  },
});

// Or get bytes directly
const bytes = encodeTicketToBytes({ /* same input */ });
```

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
  level1PublicKey: publicKeyBytes,
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
  async getPublicKey(securityProvider, keyId) {
    const key = findKeyInXml(xml, securityProvider.num!, keyId);
    if (!key) throw new Error('Key not found');
    return key;
  },
};

const result = await verifySignatures(barcodeBytes, {
  level1KeyProvider: provider,
});
```

### Verify Level 1 directly

```ts
import { verifyLevel1Signature } from 'dosipas-ts';

const result = await verifyLevel1Signature(barcodeBytes, publicKeyBytes);
```

## Extracting signed data

For custom verification workflows, extract the exact signed bytes from a barcode:

```ts
import { extractSignedData } from 'dosipas-ts';

const extracted = extractSignedData(barcodeBytes);

extracted.level1DataBytes   // bytes signed by level1Signature
extracted.level2SignedBytes // bytes signed by level2Signature
extracted.security          // security metadata (algorithms, keys, signatures)
```

## UIC public key XML utilities

```ts
import { findKeyInXml, parseKeysXml } from 'dosipas-ts';

// Find a specific key
const key = findKeyInXml(xml, 1187, 1); // issuerCode, keyId
// Returns Uint8Array or null

// Parse all keys
const keys = parseKeysXml(xml);
// [{ issuerCode, id, issuerName, publicKey, signatureAlgorithm, ... }]
```

## Built-in fixtures

The package exports hex-encoded sample tickets for testing:

```ts
import {
  SAMPLE_TICKET_HEX,
  SNCF_TER_TICKET_HEX,
  SOLEA_TICKET_HEX,
  CTS_TICKET_HEX,
  GRAND_EST_U1_FCB3_HEX,
} from 'dosipas-ts';
```

And signature fixture data:

```ts
import { SNCF_TER_SIGNATURES, SOLEA_SIGNATURES, CTS_SIGNATURES } from 'dosipas-ts';
```

## Supported algorithms

| Algorithm | Signing | Key verification |
|-----------|---------|-----------------|
| ECDSA P-256 with SHA-256 | Yes | Yes |
| ECDSA P-384 with SHA-384 | Yes | Yes |
| ECDSA P-521 with SHA-512 | Yes | Yes |
| DSA with SHA-224/256 | Detected | Not supported |

## License

MIT
