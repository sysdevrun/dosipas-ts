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
    expect(ticket.level2Signature).toBeDefined();
    expect(ticket.level2Signature!.length).toBe(64);
  });

  it('extracts security info from level1Data', () => {
    const ticket = decodeTicket(SAMPLE_TICKET_HEX);
    const l1 = ticket.level2SignedData.level1Data;
    expect(l1.securityProviderNum).toBe(3703);
    expect(l1.keyId).toBe(1);
    expect(l1.level1KeyAlg).toBe('1.2.840.10045.3.1.7');
    expect(l1.level2KeyAlg).toBe('1.2.840.10045.3.1.7');
    expect(l1.level2SigningAlg).toBe('1.2.840.10045.4.3.2');
    expect(l1.level2PublicKey).toBeDefined();
    expect(ticket.level2SignedData.level1Signature).toBeDefined();
  });

  it('decodes FCB2 rail ticket data in dataSequence', () => {
    const ticket = decodeTicket(SAMPLE_TICKET_HEX);
    const ds = ticket.level2SignedData.level1Data.dataSequence;
    expect(ds).toHaveLength(1);
    expect(ds[0].dataFormat).toBe('FCB2');

    const rt = ds[0].decoded!;
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
    const iss = ticket.level2SignedData.level1Data.dataSequence[0].decoded!.issuingDetail!;
    expect(iss.intercodeIssuing).toBeDefined();
    expect(iss.intercodeIssuing!.intercodeVersion).toBe(1);
    expect(iss.intercodeIssuing!.intercodeInstanciation).toBe(1);
    expect(iss.intercodeIssuing!.networkId).toBeDefined();
    expect(iss.intercodeIssuing!.productRetailer).toBeDefined();
    expect(iss.intercodeIssuing!.productRetailer!.retailChannel).toBe('mobileApplication');
    // Raw extension data should also be preserved
    expect(iss.extension).toBeDefined();
    expect(iss.extension!.extensionId).toMatch(/II1$/);
  });

  it('decodes transport documents with CHOICE structure', () => {
    const ticket = decodeTicket(SAMPLE_TICKET_HEX);
    const rt = ticket.level2SignedData.level1Data.dataSequence[0].decoded!;
    expect(rt.transportDocument).toBeDefined();
    expect(rt.transportDocument!.length).toBe(1);
    expect(rt.transportDocument![0].ticket.key).toBe('openTicket');
    expect(rt.transportDocument![0].ticket.value).toBeDefined();
  });

  it('decodes Intercode 6 dynamic data in level2Data', () => {
    const ticket = decodeTicket(SAMPLE_TICKET_HEX);
    const l2Data = ticket.level2SignedData.level2Data;
    expect(l2Data).toBeDefined();
    expect(l2Data!.dataFormat).toBe('_3703.ID1');
    expect(l2Data!.decoded).toBeDefined();
    const dynamic = l2Data!.decoded as any;
    expect(dynamic.dynamicContentDay).toBe(0);
    expect(dynamic.dynamicContentTime).toBe(59710);
    expect(dynamic.dynamicContentUTCOffset).toBe(-8);
    expect(dynamic.dynamicContentDuration).toBe(600);
  });
});

describe('Intercode 6 extension patterns', () => {
  describe('+<CC>II1 issuing extension (country code variant)', () => {
    it('decodes +FRII1 from Solea ticket as IntercodeIssuingData', () => {
      const ticket = decodeTicket(SOLEA_TICKET_HEX);
      const iss = ticket.level2SignedData.level1Data.dataSequence[0].decoded!.issuingDetail!;
      expect(iss.intercodeIssuing).toBeDefined();
      expect(iss.intercodeIssuing!.intercodeVersion).toBe(1);
      expect(iss.intercodeIssuing!.intercodeInstanciation).toBe(1);
      expect(iss.intercodeIssuing!.networkId).toBeDefined();
      expect(iss.intercodeIssuing!.productRetailer).toBeDefined();
      expect(iss.intercodeIssuing!.productRetailer!.retailChannel).toBe('mobileApplication');
      // Raw extension must also be preserved
      expect(iss.extension).toBeDefined();
    });

    it('decodes +FRII1 from CTS ticket as IntercodeIssuingData', () => {
      const ticket = decodeTicket(CTS_TICKET_HEX);
      const iss = ticket.level2SignedData.level1Data.dataSequence[0].decoded!.issuingDetail!;
      expect(iss.intercodeIssuing).toBeDefined();
      expect(iss.intercodeIssuing!.intercodeVersion).toBe(1);
      expect(iss.intercodeIssuing!.networkId).toBeDefined();
      expect(iss.extension).toBeDefined();
    });

    it('decodes +FRII1 from SNCF TER ticket as IntercodeIssuingData', () => {
      const ticket = decodeTicket(SNCF_TER_TICKET_HEX);
      const iss = ticket.level2SignedData.level1Data.dataSequence[0].decoded!.issuingDetail!;
      expect(iss.intercodeIssuing).toBeDefined();
      expect(iss.intercodeIssuing!.intercodeVersion).toBe(1);
      expect(iss.extension).toBeDefined();
    });
  });

  describe('_<RICS>II1 issuing extension (numeric variant)', () => {
    it('decodes _3703II1 from sample ticket', () => {
      const ticket = decodeTicket(SAMPLE_TICKET_HEX);
      const iss = ticket.level2SignedData.level1Data.dataSequence[0].decoded!.issuingDetail!;
      expect(iss.intercodeIssuing).toBeDefined();
      expect(iss.intercodeIssuing!.intercodeVersion).toBe(1);
      expect(iss.intercodeIssuing!.productRetailer!.retailChannel).toBe('mobileApplication');
    });

    it('decodes _3703II1 from Grand Est ticket', () => {
      const ticket = decodeTicket(GRAND_EST_U1_FCB3_HEX);
      const iss = ticket.level2SignedData.level1Data.dataSequence[0].decoded!.issuingDetail!;
      expect(iss.intercodeIssuing).toBeDefined();
      expect(iss.intercodeIssuing!.intercodeVersion).toBe(1);
      expect(iss.intercodeIssuing!.productRetailer!.retailChannel).toBe('mobileApplication');
    });
  });

  describe('FDC1 dynamic content data (UicDynamicContentData)', () => {
    it('decodes FDC1 from Solea ticket as UicDynamicContentData', () => {
      const ticket = decodeTicket(SOLEA_TICKET_HEX);
      const l2Data = ticket.level2SignedData.level2Data;
      expect(l2Data).toBeDefined();
      expect(l2Data!.dataFormat).toBe('FDC1');
      expect(l2Data!.decoded).toBeDefined();
    });

    it('decodes FDC1 from CTS ticket as UicDynamicContentData', () => {
      const ticket = decodeTicket(CTS_TICKET_HEX);
      expect(ticket.level2SignedData.level2Data!.dataFormat).toBe('FDC1');
      expect(ticket.level2SignedData.level2Data!.decoded).toBeDefined();
    });

    it('decodes FDC1 from Grand Est ticket as UicDynamicContentData', () => {
      const ticket = decodeTicket(GRAND_EST_U1_FCB3_HEX);
      expect(ticket.level2SignedData.level2Data!.dataFormat).toBe('FDC1');
      expect(ticket.level2SignedData.level2Data!.decoded).toBeDefined();
    });

    it('decodes FDC1 timestamp fields when present', () => {
      const ticket = decodeTicket(SOLEA_TICKET_HEX);
      const dcd = ticket.level2SignedData.level2Data!.decoded!;
      // At minimum the structure should be a valid object
      expect(typeof dcd).toBe('object');
    });
  });

  describe('_<RICS>.ID1 dynamic data (numeric variant)', () => {
    it('decodes _3703.ID1 from sample ticket', () => {
      const ticket = decodeTicket(SAMPLE_TICKET_HEX);
      const l2Data = ticket.level2SignedData.level2Data!;
      expect(l2Data.dataFormat).toBe('_3703.ID1');
      expect(l2Data.decoded).toBeDefined();
      const dynamic = l2Data.decoded as any;
      expect(dynamic.dynamicContentDay).toBe(0);
      expect(dynamic.dynamicContentDuration).toBe(600);
    });
  });
});
