import type {
  UicBarcodeTicket,
  UicBarcodeTicketInput,
  IssuingDetailInput,
  IntercodeIssuingDataInput,
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
  const rt = ticket.railTickets[0];
  if (!rt) {
    throw new Error('No rail ticket data to convert');
  }

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

  // Convert transport documents
  let transportDocument: TransportDocumentInput[] | undefined;
  if (rt.transportDocument && rt.transportDocument.length > 0) {
    transportDocument = rt.transportDocument.map((doc) => ({
      ticketType: doc.ticketType,
      ticket: { ...doc.ticket },
    }));
  }

  // Convert control detail (pass through as raw object)
  const controlDetail = rt.controlDetail
    ? (JSON.parse(JSON.stringify(rt.controlDetail)) as Record<string, unknown>)
    : undefined;

  // Convert dynamic data (FDC1 or Intercode)
  let dynamicData: IntercodeDynamicDataInput | undefined;
  let dynamicContentData: UicDynamicContentDataInput | undefined;
  if (ticket.dynamicContentData) {
    dynamicContentData = { ...ticket.dynamicContentData };
  } else if (ticket.dynamicData) {
    dynamicData = {
      rics: ticket.security.securityProviderNum ?? 0,
      dynamicContentDay: ticket.dynamicData.dynamicContentDay,
      dynamicContentTime: ticket.dynamicData.dynamicContentTime,
      dynamicContentUTCOffset: ticket.dynamicData.dynamicContentUTCOffset,
      dynamicContentDuration: ticket.dynamicData.dynamicContentDuration,
    };
  }

  const result: UicBarcodeTicketInput = {
    headerVersion: ticket.headerVersion,
    fcbVersion: rt.fcbVersion,
    securityProviderNum: ticket.security.securityProviderNum,
    keyId: ticket.security.keyId,
    endOfValidityYear: ticket.security.endOfValidityYear,
    endOfValidityDay: ticket.security.endOfValidityDay,
    endOfValidityTime: ticket.security.endOfValidityTime,
    validityDuration: ticket.security.validityDuration,
    level1KeyAlg: ticket.security.level1KeyAlg,
    level1SigningAlg: ticket.security.level1SigningAlg,
    level1Signature: ticket.security.level1Signature,
    level2KeyAlg: ticket.security.level2KeyAlg,
    level2SigningAlg: ticket.security.level2SigningAlg,
    level2PublicKey: ticket.security.level2PublicKey,
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
