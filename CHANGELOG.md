# Changelog

## [1.4.0]

### Breaking Changes

- **`encodeLevel2Data`** now returns `RawBytes` instead of `{ dataFormat: string; data: Uint8Array }` and requires a `format` parameter (e.g. `"U2"`). This aligns it with `encodeLevel1Data` for bit-precise signature reproducibility.
- **`encodeLevel2SignedData`** now accepts `RawBytes` for its `level2Data` option instead of `{ dataFormat: string; data: Uint8Array }`.

### Migration

```diff
-const l2 = encodeLevel2Data(level2Data);
-console.log(l2.dataFormat);  // no longer available
+const l2 = encodeLevel2Data(level2Data, 'U2');
 console.log(l2.data);        // still works — Uint8Array
```
