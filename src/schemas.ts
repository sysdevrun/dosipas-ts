/**
 * Embedded JSON schemas for UIC barcode decoding.
 * These are imported at build time and bundled into the compiled module.
 */
import type { SchemaNode } from 'asn1-per-ts';

import headerV1 from '../schemas/uic-barcode/uicBarcodeHeader_v1.schema.json';
import headerV2 from '../schemas/uic-barcode/uicBarcodeHeader_v2.schema.json';
import railTicketV1 from '../schemas/uic-barcode/uicRailTicketData_v1.schema.json';
import railTicketV2 from '../schemas/uic-barcode/uicRailTicketData_v2.schema.json';
import railTicketV3 from '../schemas/uic-barcode/uicRailTicketData_v3.schema.json';
import intercode6 from '../schemas/uic-barcode/intercode6.schema.json';

type SchemaMap = Record<string, SchemaNode>;

export const HEADER_SCHEMAS: Record<number, SchemaMap> = {
  1: headerV1 as unknown as SchemaMap,
  2: headerV2 as unknown as SchemaMap,
};

export const RAIL_TICKET_SCHEMAS: Record<number, SchemaMap> = {
  1: railTicketV1 as unknown as SchemaMap,
  2: railTicketV2 as unknown as SchemaMap,
  3: railTicketV3 as unknown as SchemaMap,
};

export const INTERCODE_SCHEMAS = intercode6 as unknown as SchemaMap;
