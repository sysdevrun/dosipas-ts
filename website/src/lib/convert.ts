import type {
  UicBarcodeTicket,
  UicBarcodeTicketInput,
  IssuingDetailInput,
  IntercodeIssuingDataInput,
  IntercodeDynamicData,
  IntercodeDynamicDataInput,
  UicDynamicContentDataInput,
  TravelerDetailInput,
  TransportDocumentInput,
} from 'dosipas-ts';

/**
 * Convert a decoded UicBarcodeTicket into a UicBarcodeTicketInput
 * suitable for the encode form.
 *
 * Signatures, signing OIDs, and Level 2 public key are preserved so that
 * the Encode tab can pre-populate its signature fields for editing.
 */
export function ticketToInput(ticket: UicBarcodeTicket): UicBarcodeTicketInput {
  const l1 = ticket.level2SignedData.level1Data;
  const ds = l1.dataSequence[0];
  if (!ds?.decoded) {
    throw new Error('No decoded rail ticket data to convert');
  }
  const rt = ds.decoded;
  const fcbMatch = ds.dataFormat.match(/^FCB(\d+)$/);
  const fcbVersion = fcbMatch ? parseInt(fcbMatch[1], 10) : 2;
  const iss = rt.issuingDetail;

  const issuingDetail: IssuingDetailInput = {
    securityProviderNum: iss?.securityProviderNum,
    issuerNum: iss?.issuerNum,
    issuingYear: iss?.issuingYear ?? new Date().getFullYear(),
    issuingDay: iss?.issuingDay ?? 1,
    issuingTime: iss?.issuingTime,
    issuerName: iss?.issuerName,
    specimen: iss?.specimen,
    securePaperTicket: iss?.securePaperTicket,
    activated: iss?.activated,
    currency: iss?.currency,
    currencyFract: iss?.currencyFract,
    issuerPNR: iss?.issuerPNR,
  };

  // Convert intercode issuing extension if present
  if (iss?.intercodeIssuing) {
    const ic = iss.intercodeIssuing;
    const intercodeIssuing: IntercodeIssuingDataInput = {
      extensionId: ic.extensionId,
      intercodeVersion: ic.intercodeVersion,
      intercodeInstanciation: ic.intercodeInstanciation,
      networkId: ic.networkId,
      productRetailer: ic.productRetailer,
    };
    issuingDetail.intercodeIssuing = intercodeIssuing;
  }

  // Convert traveler detail
  let travelerDetail: TravelerDetailInput | undefined;
  if (rt.travelerDetail) {
    travelerDetail = {
      traveler: rt.travelerDetail.traveler?.map((t) => ({ ...t })),
      preferredLanguage: rt.travelerDetail.preferredLanguage,
      groupName: rt.travelerDetail.groupName,
    };
  }

  // Convert transport documents (CHOICE {key, value} -> {ticketType, ticket})
  let transportDocument: TransportDocumentInput[] | undefined;
  if (rt.transportDocument && rt.transportDocument.length > 0) {
    transportDocument = rt.transportDocument.map((doc) => ({
      ticketType: doc.ticket.key,
      ticket: { ...doc.ticket.value },
    }));
  }

  // Convert control detail (pass through as raw object)
  const controlDetail = rt.controlDetail
    ? (JSON.parse(JSON.stringify(rt.controlDetail)) as Record<string, unknown>)
    : undefined;

  // Convert dynamic data (FDC1 or Intercode)
  let dynamicData: IntercodeDynamicDataInput | undefined;
  let dynamicContentData: UicDynamicContentDataInput | undefined;
  const l2Data = ticket.level2SignedData.level2Data;
  if (l2Data?.decoded) {
    if (l2Data.dataFormat === 'FDC1') {
      dynamicContentData = { ...(l2Data.decoded as UicDynamicContentDataInput) };
    } else {
      const ricsMatch = l2Data.dataFormat.match(/^_(\d+)\.ID1$/);
      const rics = ricsMatch ? parseInt(ricsMatch[1], 10) : l1.securityProviderNum ?? 0;
      const dynamic = l2Data.decoded as IntercodeDynamicData;
      dynamicData = {
        rics,
        dynamicContentDay: dynamic.dynamicContentDay,
        dynamicContentTime: dynamic.dynamicContentTime,
        dynamicContentUTCOffset: dynamic.dynamicContentUTCOffset,
        dynamicContentDuration: dynamic.dynamicContentDuration,
      };
    }
  }

  const result: UicBarcodeTicketInput = {
    headerVersion: parseInt(ticket.format.replace('U', ''), 10),
    fcbVersion,
    securityProviderNum: l1.securityProviderNum,
    keyId: l1.keyId,
    endOfValidityYear: l1.endOfValidityYear,
    endOfValidityDay: l1.endOfValidityDay,
    endOfValidityTime: l1.endOfValidityTime,
    validityDuration: l1.validityDuration,
    level1KeyAlg: l1.level1KeyAlg,
    level1SigningAlg: l1.level1SigningAlg,
    level1Signature: ticket.level2SignedData.level1Signature,
    level2KeyAlg: l1.level2KeyAlg,
    level2SigningAlg: l1.level2SigningAlg,
    level2PublicKey: l1.level2PublicKey,
    level2Signature: ticket.level2Signature,
    railTicket: {
      issuingDetail,
      travelerDetail,
      transportDocument,
      controlDetail,
    },
    dynamicData,
    dynamicContentData,
  };

  return result;
}
