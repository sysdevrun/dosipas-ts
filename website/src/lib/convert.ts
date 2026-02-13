import type {
  UicBarcodeTicket,
  UicBarcodeTicketInput,
  IssuingDetailInput,
  IntercodeIssuingDataInput,
  IntercodeDynamicDataInput,
  TravelerDetailInput,
  TransportDocumentInput,
} from 'dosipas-ts';

/**
 * Convert a decoded UicBarcodeTicket into a UicBarcodeTicketInput
 * suitable for the encode form.
 *
 * Security fields (signatures, keys, OIDs) are intentionally omitted
 * since those will be set by the signing key inputs in the Encode tab.
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

  // Convert dynamic data
  let dynamicData: IntercodeDynamicDataInput | undefined;
  if (ticket.dynamicData) {
    dynamicData = {
      rics: ticket.security.securityProviderNum ?? 0,
      dynamicContentDay: ticket.dynamicData.dynamicContentDay,
      dynamicContentTime: ticket.dynamicData.dynamicContentTime,
      dynamicContentUTCOffset: ticket.dynamicData.dynamicContentUTCOffset,
      dynamicContentDuration: ticket.dynamicData.dynamicContentDuration,
    };
  }

  return {
    headerVersion: ticket.headerVersion,
    fcbVersion: rt.fcbVersion,
    securityProviderNum: ticket.security.securityProviderNum,
    keyId: ticket.security.keyId,
    endOfValidityYear: ticket.security.endOfValidityYear,
    endOfValidityDay: ticket.security.endOfValidityDay,
    endOfValidityTime: ticket.security.endOfValidityTime,
    validityDuration: ticket.security.validityDuration,
    railTicket: {
      issuingDetail,
      travelerDetail,
      transportDocument,
      controlDetail,
    },
    dynamicData,
  };
}
