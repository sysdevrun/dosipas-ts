/**
 * Compile the UIC Dynamic Content Data ASN.1 schema (FDC1) to JSON SchemaNode format.
 *
 * Usage: node scripts/compile-fdc1.mjs
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { parseAsn1Module, convertModuleToSchemaNodes } from 'asn1-per-ts';

const asn1Source = readFileSync('schemas/uic-barcode/uicDynamicContentData_v1.asn', 'utf-8');
const module = parseAsn1Module(asn1Source);
const schemas = convertModuleToSchemaNodes(module);

const outPath = 'schemas/uic-barcode/uicDynamicContentData_v1.schema.json';
writeFileSync(outPath, JSON.stringify(schemas, null, 2) + '\n');
console.log(`Wrote ${outPath} with types: ${Object.keys(schemas).join(', ')}`);
