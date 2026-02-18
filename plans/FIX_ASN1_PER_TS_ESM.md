# Fix: asn1-per-ts v1.2.0 broken ESM build

## Problem

v1.2.0 was published with `"type": "module"` in package.json but the TypeScript build output uses extensionless imports (e.g. `from './BitBuffer'` instead of `from './BitBuffer.js'`). Node.js ESM resolution requires explicit `.js` extensions for relative imports.

This was caused by `tsconfig.build.json` using `"moduleResolution": "bundler"` which doesn't enforce extensions, while the published package needs `"moduleResolution": "nodenext"` (or `"node16"`) to emit `.js` extensions.

v1.0.1 had correct `.js` extensions. The regression was introduced in the v1.2.0 build.

## Fix

In the `asn1-per-ts` repo:

1. Change `tsconfig.build.json`:
```json
{
  "extends": "./tsconfig.json",
  "compilerOptions": {
    "module": "NodeNext",
    "moduleResolution": "NodeNext"
  },
  "exclude": ["node_modules", "dist", "tests", "website", "**/*.test.ts"]
}
```

2. Add `.js` extensions to all relative imports in `src/` files. TypeScript with `moduleResolution: "nodenext"` requires `.js` extensions in import specifiers (even though the source files are `.ts`). For example:
```ts
// Before:
import { BitBuffer } from './BitBuffer';
// After:
import { BitBuffer } from './BitBuffer.js';
```

3. Rebuild and publish as v1.2.1.

## Affected files (imports to fix)

Every `.ts` file in `src/` that has relative imports needs `.js` extensions added. Key files:
- `src/index.ts` (re-exports all modules)
- `src/helpers.ts`
- `src/codecs/*.ts`
- `src/schema/*.ts`
- `src/parser/*.ts`
