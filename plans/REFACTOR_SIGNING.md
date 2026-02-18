# Plan: Decompose signing into composable encoding + signing primitives

## Motivation

The current `signLevel1` and `signAndEncodeTicket` couple encoding and signing into monolithic functions. The goal is to split them into independent, composable steps that mirror the actual UIC barcode wire format:

```
UicBarcodeHeader
├── format                          ← string like "U2"
├── level2SignedData                ← SIGNED BY level2Signature
│   ├── level1Data                  ← SIGNED BY level1Signature
│   │   ├── securityProviderNum, keyId, dataSequence, OIDs, publicKey, validity...
│   ├── level1Signature
│   └── level2Data (optional)
└── level2Signature
```

## New functions

### 1. `encodeLevel1Structure(input): Uint8Array`

**Purpose:** Encode only the `level1Data` SEQUENCE to bytes. Since `level1Signature` sits *outside* `level1Data` (it's a sibling in `level2SignedData`), no key or signature is needed here.

**Input type — new `Level1Input`:**
```ts
interface Level1Input {
  headerVersion?: number;       // 1 or 2 (default 2)
  fcbVersion?: number;          // 1, 2, or 3 (default 2)
  securityProviderNum?: number;
  keyId?: number;
  level1KeyAlg?: string;        // OID
  level2KeyAlg?: string;        // OID
  level1SigningAlg?: string;    // OID
  level2SigningAlg?: string;    // OID
  level2PublicKey?: Uint8Array;
  endOfValidityYear?: number;   // v2 only
  endOfValidityDay?: number;
  endOfValidityTime?: number;
  validityDuration?: number;
  railTicket: RailTicketInput;  // reuse existing type
}
```

**Implementation approach:**
- Reuse the existing `encodeRailTicket()` helper to produce the `dataSequence` entry bytes.
- Build the `level1Data` object matching the ASN.1 schema structure.
- Encode *just* `level1Data` using the header schema's `level1Data` sub-codec.
- Return the raw PER-encoded bytes of `level1Data`.

**Key challenge — encoding a sub-structure in isolation:**
The current `SchemaCodec` encodes the full `UicBarcodeHeader` from root. To encode just `level1Data`, we need one of:

- **Option A (recommended): Build a standalone codec from the `level1Data` schema node.** Extract the `level1Data` field definition from the header schema JSON and pass it to `SchemaBuilder.build()` or `new SchemaCodec()`. This is clean but requires the schema node to be accessible (it's a nested field inside the header schema).
- **Option B: Encode the full header with dummy wrappers, then extract `level1Data` bytes.** Encode a complete `UicBarcodeHeader` with placeholder signatures, then use `extractSignedData()` to get `level1DataBytes`. This is what the current `signLevel1` already does — it works but defeats the purpose of decomposition.
- **Option C: Walk the header schema JSON at runtime to extract the nested `level1Data` type definition.** Parse the schema to find the field named `level1Data` inside `level2SignedData`, get its `schema` node, and build a codec from it. This is clean and doesn't require schema file changes.

**Recommendation:** Option C — walk the existing header schema JSON to extract `level1Data`'s schema node, then `new SchemaCodec(level1DataSchemaNode)`. This keeps schemas as the single source of truth and requires no schema file modifications. A small helper like `extractFieldSchema(headerSchema, 'level2SignedData.level1Data')` would make this reusable for `level2SignedData` as well.

### 2. `signPayload(data, privateKey, curve): Uint8Array`

**Purpose:** Pure signing function. Takes arbitrary bytes, signs them with ECDSA, returns DER signature.

**Signature:**
```ts
function signPayload(
  data: Uint8Array,
  privateKey: Uint8Array,
  curve: CurveName,
): Uint8Array
```

**Implementation:** Essentially the existing `ecSign()` function made public. Uses `@noble/curves` with `prehash: true, lowS: false`, then `rawToDer()`.

**Usable for both levels:**
- Level 1: `signPayload(level1Bytes, l1PrivateKey, 'P-256')`
- Level 2: `signPayload(level2Bytes, l2PrivateKey, 'P-256')`

### 3. `encodeLevel2Structure(input): Uint8Array`

**Purpose:** Encode the `level2SignedData` SEQUENCE. This contains `level1Data`, `level1Signature`, and optionally `level2Data`. The `level2Signature` sits *outside* this structure (it's a sibling at the header root), so no L2 key/signature needed.

**Input type — new `Level2Input`:**
```ts
interface Level2Input {
  level1Data: Uint8Array;       // pre-encoded level1Data bytes (from encodeLevel1Structure)
  level1Signature: Uint8Array;  // DER signature bytes (from signPayload)
  level2Data?: {                // optional dynamic content
    dataFormat: string;         // e.g. "FDC1" or "_3703.ID1"
    data: Uint8Array;           // pre-encoded payload bytes
  };
}
```

**Implementation approach:**
- Extract the `level2SignedData` schema node from the header schema (same technique as for `level1Data`).
- The tricky part: `level1Data` is provided as **pre-encoded raw bytes**, but the ASN.1 codec expects a structured object to encode.

**Integrating raw payload bytes — see dedicated section below.**

### 4. `encodeUicBarcodeHeader(input): Uint8Array`

**Purpose:** Encode the outermost `UicBarcodeHeader` SEQUENCE.

**Input type — new `HeaderInput`:**
```ts
interface HeaderInput {
  format: string;                  // "U1" or "U2"
  level2SignedData: Uint8Array;    // pre-encoded (from encodeLevel2Structure)
  level2Signature?: Uint8Array;    // DER signature bytes (from signPayload)
}
```

**Same raw-bytes integration challenge as `encodeLevel2Structure`.**

---

## Integrating raw payload bytes into ASN.1 PER encoding

This is the core design challenge. `encodeLevel2Structure` receives `level1Data` as pre-encoded `Uint8Array`, but the ASN.1 PER codec expects structured objects. Three approaches:

### Approach A: Raw-bytes passthrough in the codec (recommended)

Add support in `asn1-per-ts` for a sentinel/marker that tells the encoder "write these bytes verbatim instead of encoding this field."

```ts
// In asn1-per-ts, add a marker type:
const RAW = Symbol('raw');

// Usage:
const level2Obj = {
  level1Data: { [RAW]: level1DataBytes },  // passthrough
  level1Signature: signatureBytes,
  level2Data: level2DataObj,
};
codec.encode(level2Obj);
```

**Pros:** Clean API, no schema modifications, bytes are bit-exact.
**Cons:** Requires a change to `asn1-per-ts`.

### Approach B: OCTET STRING wrapping with schema modification

Change the schema so that `level1Data` inside `level2SignedData` is declared as `OCTET STRING` rather than a `SEQUENCE`. Then the codec treats it as opaque bytes.

But this fundamentally breaks decoding — the decoder needs the full structure to parse `level1Data`.

**Verdict:** Not viable without maintaining two parallel schemas (one for encoding, one for decoding).

### Approach C: Manual byte concatenation (no codec for outer layers)

Build `level2SignedData` bytes manually by concatenating PER-encoded fragments:
```ts
function encodeLevel2Structure(input: Level2Input): Uint8Array {
  // Manually write the PER encoding:
  // - optional bitmap for level2SignedData fields
  // - level1Data raw bytes (verbatim)
  // - level1Signature as OCTET STRING
  // - level2Data (if present) as sub-structure
}
```

**Pros:** No changes to `asn1-per-ts`, full control over byte layout.
**Cons:** Fragile — tightly coupled to the PER encoding rules and schema layout. Any schema change requires manual update. Error-prone for optional fields / extension markers.

### Approach D: Decode-then-reencode with override

Decode the raw `level1Data` bytes back into a structured object, then pass it normally to the codec as part of `level2SignedData`. This guarantees the bytes are structurally valid but does NOT guarantee bit-exact reproduction (the codec may encode differently than the original).

**Pros:** Uses the codec as intended, no changes needed.
**Cons:** Not bit-exact. The re-encoded `level1Data` might differ from the input bytes, which would invalidate the Level 2 signature (since it signs the `level2SignedData` bytes, which include `level1Data`).

### Recommendation

**Approach A** is the cleanest long-term solution. It requires adding a "raw bytes passthrough" feature to `asn1-per-ts`, which is a generally useful capability (e.g., for any "embed pre-encoded sub-structure" use case in ASN.1).

The API in `asn1-per-ts` could look like:
```ts
import { RawBytes } from 'asn1-per-ts';

// When encoding, any field value wrapped in RawBytes is written verbatim
const obj = {
  level1Data: new RawBytes(preEncodedBytes),
  level1Signature: sigBytes,
};
```

The encoder, when it encounters a `RawBytes` instance for a SEQUENCE/SET field, writes the bytes directly to the `BitBuffer` instead of recursing into the field's schema.

**Fallback:** If modifying `asn1-per-ts` is not desirable, Approach C (manual concatenation) works but should be accompanied by thorough tests to ensure the manual PER encoding matches what the codec produces.

---

## Composed usage (end-to-end flow)

```ts
// 1. Encode level1Data
const level1Bytes = encodeLevel1Structure({
  securityProviderNum: 1080,
  keyId: 1,
  level1KeyAlg: '1.2.840.10045.3.1.7',
  level1SigningAlg: '1.2.840.10045.4.3.2',
  level2KeyAlg: '...',
  level2SigningAlg: '...',
  level2PublicKey: l2PublicKeyBytes,
  railTicket: { ... },
});

// 2. Sign level1Data
const level1Sig = signPayload(level1Bytes, l1PrivateKey, 'P-256');

// 3. Encode level2SignedData (contains level1Data + signature + optional dynamic data)
const level2Bytes = encodeLevel2Structure({
  level1Data: level1Bytes,
  level1Signature: level1Sig,
  level2Data: { dataFormat: 'FDC1', data: fdc1Bytes },
});

// 4. Sign level2SignedData
const level2Sig = signPayload(level2Bytes, l2PrivateKey, 'P-256');

// 5. Encode final barcode header
const barcode = encodeUicBarcodeHeader({
  format: 'U2',
  level2SignedData: level2Bytes,
  level2Signature: level2Sig,
});
```

## Migration strategy

1. Add the new functions alongside the existing ones (non-breaking).
2. Reimplement `signAndEncodeTicket` on top of the new primitives (to validate equivalence).
3. Deprecate `signLevel1`, `signLevel2`, `signAndEncodeTicket` once callers migrate.
4. Update tests: add unit tests for each new function, keep existing round-trip tests passing.

## Files to modify

| File | Changes |
|------|---------|
| `src/encoder.ts` | Add `encodeLevel1Structure`, `encodeLevel2Structure`, `encodeUicBarcodeHeader`. Extract `encodeRailTicket` reuse. Add schema-node extraction helper. |
| `src/signer.ts` | Add `signPayload` (public). Optionally reimplement existing functions on top of new primitives. |
| `src/types.ts` | Add `Level1Input`, `Level2Input`, `HeaderInput` types. |
| `src/index.ts` | Export new functions and types. |
| `asn1-per-ts` (upstream) | If Approach A: add `RawBytes` passthrough support. |
| `tests/signer.test.ts` | Add tests for new primitives, verify round-trip equivalence. |
