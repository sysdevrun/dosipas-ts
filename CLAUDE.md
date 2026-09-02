# CLAUDE.md

## Project overview

dosipas-ts is a TypeScript npm module for encoding, decoding, and verifying UIC barcode tickets with Intercode 6 extensions. It is the high-level application layer built on top of `asn1-per-ts` (the low-level ASN.1 PER codec).

## Project structure

- `src/` - Source code (decoder, encoder, verifier, signature utilities, schemas, fixtures)
- `tests/` - Vitest unit tests
- `schemas/uic-barcode/` - Pre-compiled JSON schemas for UIC barcode headers, rail ticket data, and Intercode 6

## Commands

- `npm test` - Run all unit tests with Vitest
- `npm run build` - Build the library to `dist/` via TypeScript compiler
- `npx tsc --noEmit` - Type-check without emitting

## Code conventions

- TypeScript strict mode enabled, ESM-only (`"type": "module"`)
- All type-only re-exports use `export type { ... }`
- Tests use Vitest (API-compatible with Jest: `describe`/`it`/`expect`)
- Test files live in `tests/` (not colocated)
- JSON schemas are imported at build time via `resolveJsonModule`

## Changelog

- Update `CHANGELOG.md` when making user-facing changes (new features, breaking changes, bug fixes)
- Pending entries go at the top under `## Upcoming release` — never under a guessed
  next version number, and do not bump `package.json` for them: the version a change
  ships in is decided at release time
- At release time, rename `## Upcoming release` to the version (e.g. `## [1.5.2]`),
  bump `package.json` to match, and leave a fresh empty `## Upcoming release` header
  above it

## Dependencies

- `asn1-per-ts` — Low-level ASN.1 PER codec (from npm)
- `@noble/curves` — ECDSA signature verification
- `@noble/hashes` — Cryptographic hashing
