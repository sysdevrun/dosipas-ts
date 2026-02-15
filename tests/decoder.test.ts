import {
  decodeTicket,
  SAMPLE_TICKET_HEX,
  SOLEA_TICKET_HEX,
  CTS_TICKET_HEX,
  SNCF_TER_TICKET_HEX,
  GRAND_EST_U1_FCB3_HEX,
} from '../src';

describe('decodeTicket', () => {
  it('decodes the sample fixture', () => {
    const ticket = decodeTicket(SAMPLE_TICKET_HEX);

    expect(ticket.format).toBe('U1');
    expect(ticket.headerVersion).toBe(1);
    expect(ticket.level2Signature).toBeDefined();
    expect(ticket.level2Signature!.length).toBe(64);
  });

  it('extracts security info', () => {
    const ticket = decodeTicket(SAMPLE_TICKET_HEX);
    expect(ticket.security.securityProviderNum).toBe(3703);
    expect(ticket.security.keyId).toBe(1);
    expect(ticket.security.level1KeyAlg).toBe('1.2.840.10045.3.1.7');
    expect(ticket.security.level2KeyAlg).toBe('1.2.840.10045.3.1.7');
    expect(ticket.security.level2SigningAlg).toBe('1.2.840.10045.4.3.2');
    expect(ticket.security.level2PublicKey).toBeDefined();
    expect(ticket.security.level1Signature).toBeDefined();
  });

  it('decodes FCB2 rail ticket data', () => {
    const ticket = decodeTicket(SAMPLE_TICKET_HEX);
    expect(ticket.railTickets).toHaveLength(1);

    const rt = ticket.railTickets[0];
    expect(rt.fcbVersion).toBe(2);
    expect(rt.issuingDetail).toBeDefined();
    expect(rt.issuingDetail!.issuingYear).toBe(2020);
    expect(rt.issuingDetail!.issuingDay).toBe(121);
    expect(rt.issuingDetail!.issuingTime).toBe(995);
    expect(rt.issuingDetail!.specimen).toBe(false);
    expect(rt.issuingDetail!.activated).toBe(true);
    expect(rt.issuingDetail!.currency).toBe('EUR');
    expect(rt.issuingDetail!.currencyFract).toBe(2);
  });

  it('decodes Intercode 6 issuing extension', () => {
    const ticket = decodeTicket(SAMPLE_TICKET_HEX);
    const iss = ticket.railTickets[0].issuingDetail!;
    expect(iss.intercodeIssuing).toBeDefined();
    expect(iss.intercodeIssuing!.intercodeVersion).toBe(1);
    expect(iss.intercodeIssuing!.intercodeInstanciation).toBe(1);
    expect(iss.intercodeIssuing!.networkId).toBeDefined();
    expect(iss.intercodeIssuing!.productRetailer).toBeDefined();
    expect(iss.intercodeIssuing!.productRetailer!.retailChannel).toBe('mobileApplication');
  });

  it('decodes transport documents', () => {
    const ticket = decodeTicket(SAMPLE_TICKET_HEX);
    const rt = ticket.railTickets[0];
    expect(rt.transportDocument).toBeDefined();
    expect(rt.transportDocument!.length).toBe(1);
    expect(rt.transportDocument![0].ticketType).toBe('openTicket');
  });

  it('decodes Intercode 6 dynamic data', () => {
    const ticket = decodeTicket(SAMPLE_TICKET_HEX);
    expect(ticket.dynamicData).toBeDefined();
    expect(ticket.dynamicData!.dynamicContentDay).toBe(0);
    expect(ticket.dynamicData!.dynamicContentTime).toBe(59710);
    expect(ticket.dynamicData!.dynamicContentUTCOffset).toBe(-8);
    expect(ticket.dynamicData!.dynamicContentDuration).toBe(600);
  });

  it('includes level2 data block', () => {
    const ticket = decodeTicket(SAMPLE_TICKET_HEX);
    expect(ticket.level2DataBlock).toBeDefined();
    expect(ticket.level2DataBlock!.dataFormat).toBe('_3703.ID1');
  });
});

describe('Intercode 6 extension patterns', () => {
  describe('+<CC>II1 issuing extension (country code variant)', () => {
    it('decodes +FRII1 from Soléa ticket as IntercodeIssuingData', () => {
      const ticket = decodeTicket(SOLEA_TICKET_HEX);
      const iss = ticket.railTickets[0].issuingDetail!;
      expect(iss.intercodeIssuing).toBeDefined();
      expect(iss.intercodeIssuing!.intercodeVersion).toBe(1);
      expect(iss.intercodeIssuing!.intercodeInstanciation).toBe(1);
      expect(iss.intercodeIssuing!.networkId).toBeDefined();
      expect(iss.intercodeIssuing!.productRetailer).toBeDefined();
      expect(iss.intercodeIssuing!.productRetailer!.retailChannel).toBe('mobileApplication');
      // Must NOT fall through as raw extension
      expect(iss.extension).toBeUndefined();
    });

    it('decodes +FRII1 from CTS ticket as IntercodeIssuingData', () => {
      const ticket = decodeTicket(CTS_TICKET_HEX);
      const iss = ticket.railTickets[0].issuingDetail!;
      expect(iss.intercodeIssuing).toBeDefined();
      expect(iss.intercodeIssuing!.intercodeVersion).toBe(1);
      expect(iss.intercodeIssuing!.networkId).toBeDefined();
      expect(iss.extension).toBeUndefined();
    });

    it('decodes +FRII1 from SNCF TER ticket as IntercodeIssuingData', () => {
      const ticket = decodeTicket(SNCF_TER_TICKET_HEX);
      const iss = ticket.railTickets[0].issuingDetail!;
      expect(iss.intercodeIssuing).toBeDefined();
      expect(iss.intercodeIssuing!.intercodeVersion).toBe(1);
      expect(iss.extension).toBeUndefined();
    });
  });

  describe('_<RICS>II1 issuing extension (numeric variant)', () => {
    it('decodes _3703II1 from sample ticket', () => {
      const ticket = decodeTicket(SAMPLE_TICKET_HEX);
      const iss = ticket.railTickets[0].issuingDetail!;
      expect(iss.intercodeIssuing).toBeDefined();
      expect(iss.intercodeIssuing!.intercodeVersion).toBe(1);
      expect(iss.intercodeIssuing!.productRetailer!.retailChannel).toBe('mobileApplication');
    });

    it('decodes _3703II1 from Grand Est ticket', () => {
      const ticket = decodeTicket(GRAND_EST_U1_FCB3_HEX);
      const iss = ticket.railTickets[0].issuingDetail!;
      expect(iss.intercodeIssuing).toBeDefined();
      expect(iss.intercodeIssuing!.intercodeVersion).toBe(1);
      expect(iss.intercodeIssuing!.productRetailer!.retailChannel).toBe('mobileApplication');
    });
  });

  describe('FDC1 dynamic content data (UicDynamicContentData)', () => {
    it('decodes FDC1 from Soléa ticket as UicDynamicContentData', () => {
      const ticket = decodeTicket(SOLEA_TICKET_HEX);
      expect(ticket.level2DataBlock).toBeDefined();
      expect(ticket.level2DataBlock!.dataFormat).toBe('FDC1');
      expect(ticket.dynamicContentData).toBeDefined();
      // FDC1 should NOT populate the Intercode dynamicData field
      expect(ticket.dynamicData).toBeUndefined();
    });

    it('decodes FDC1 from CTS ticket as UicDynamicContentData', () => {
      const ticket = decodeTicket(CTS_TICKET_HEX);
      expect(ticket.level2DataBlock!.dataFormat).toBe('FDC1');
      expect(ticket.dynamicContentData).toBeDefined();
      expect(ticket.dynamicData).toBeUndefined();
    });

    it('decodes FDC1 from Grand Est ticket as UicDynamicContentData', () => {
      const ticket = decodeTicket(GRAND_EST_U1_FCB3_HEX);
      expect(ticket.level2DataBlock!.dataFormat).toBe('FDC1');
      expect(ticket.dynamicContentData).toBeDefined();
      expect(ticket.dynamicData).toBeUndefined();
    });

    it('decodes FDC1 timestamp fields when present', () => {
      const ticket = decodeTicket(SOLEA_TICKET_HEX);
      const dcd = ticket.dynamicContentData!;
      // At minimum the structure should be a valid object
      expect(typeof dcd).toBe('object');
    });
  });

  describe('_<RICS>.ID1 dynamic data (numeric variant)', () => {
    it('decodes _3703.ID1 from sample ticket', () => {
      const ticket = decodeTicket(SAMPLE_TICKET_HEX);
      expect(ticket.level2DataBlock!.dataFormat).toBe('_3703.ID1');
      expect(ticket.dynamicData).toBeDefined();
      expect(ticket.dynamicData!.dynamicContentDay).toBe(0);
      expect(ticket.dynamicData!.dynamicContentDuration).toBe(600);
    });
  });
});
