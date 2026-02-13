import type { UicBarcodeTicket, SecurityInfo, RailTicketData, IssuingDetail, IntercodeIssuingData, IntercodeDynamicData, TravelerDetail, TransportDocumentEntry, ControlDetail } from 'dosipas-ts';
import JsonTree from './JsonTree';

interface Props {
  ticket: UicBarcodeTicket;
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide">{title}</h3>
      <div className="bg-white rounded-lg border border-gray-200 p-3 text-sm">{children}</div>
    </div>
  );
}

function Field({ label, value }: { label: string; value?: string | number | boolean | null }) {
  if (value === undefined || value === null) return null;
  return (
    <div className="flex gap-2 py-0.5">
      <span className="text-gray-500 min-w-32 shrink-0">{label}</span>
      <span className="font-mono text-gray-900">
        {typeof value === 'boolean' ? (value ? 'Yes' : 'No') : String(value)}
      </span>
    </div>
  );
}

function BytesField({ label, value }: { label: string; value?: Uint8Array }) {
  if (!value) return null;
  const hex = Array.from(value).map(b => b.toString(16).padStart(2, '0')).join(' ');
  const display = hex.length > 80 ? hex.slice(0, 77) + '...' : hex;
  return (
    <div className="flex gap-2 py-0.5">
      <span className="text-gray-500 min-w-32 shrink-0">{label}</span>
      <span className="font-mono text-gray-900 text-xs break-all" title={hex}>{display}</span>
    </div>
  );
}

const OID_NAMES: Record<string, string> = {
  '1.2.840.10045.4.3.2': 'ECDSA SHA-256',
  '1.2.840.10045.4.3.3': 'ECDSA SHA-384',
  '1.2.840.10045.4.3.4': 'ECDSA SHA-512',
  '2.16.840.1.101.3.4.3.1': 'DSA SHA-224',
  '2.16.840.1.101.3.4.3.2': 'DSA SHA-256',
  '1.2.840.10045.3.1.7': 'P-256',
  '1.3.132.0.34': 'P-384',
  '1.3.132.0.35': 'P-521',
  '1.2.840.113549.1.1.1': 'RSA',
  '1.2.840.113549.1.1.11': 'RSA SHA-256',
};

function oidName(oid?: string): string | undefined {
  if (!oid) return undefined;
  return OID_NAMES[oid] ?? oid;
}

function SecuritySection({ security }: { security: SecurityInfo }) {
  return (
    <Section title="Security">
      <Field label="Provider" value={security.securityProviderNum} />
      <Field label="Provider (IA5)" value={security.securityProviderIA5} />
      <Field label="Key ID" value={security.keyId} />
      <Field label="L1 Key Alg" value={oidName(security.level1KeyAlg)} />
      <Field label="L2 Key Alg" value={oidName(security.level2KeyAlg)} />
      <Field label="L1 Signing Alg" value={oidName(security.level1SigningAlg)} />
      <Field label="L2 Signing Alg" value={oidName(security.level2SigningAlg)} />
      <BytesField label="L2 Public Key" value={security.level2PublicKey} />
      <BytesField label="L1 Signature" value={security.level1Signature} />
      <Field label="Validity Year" value={security.endOfValidityYear} />
      <Field label="Validity Day" value={security.endOfValidityDay} />
      <Field label="Validity Time" value={security.endOfValidityTime} />
      <Field label="Validity Duration" value={security.validityDuration} />
    </Section>
  );
}

function IssuingSection({ detail }: { detail: IssuingDetail }) {
  return (
    <Section title="Issuing Detail">
      <Field label="Provider" value={detail.securityProviderNum} />
      <Field label="Issuer" value={detail.issuerNum} />
      <Field label="Issuer (IA5)" value={detail.issuerIA5} />
      <Field label="Issuer Name" value={detail.issuerName} />
      <Field label="Year" value={detail.issuingYear} />
      <Field label="Day" value={detail.issuingDay} />
      <Field label="Time" value={detail.issuingTime} />
      <Field label="Specimen" value={detail.specimen} />
      <Field label="Secure Paper" value={detail.securePaperTicket} />
      <Field label="Activated" value={detail.activated} />
      <Field label="Currency" value={detail.currency} />
      <Field label="Currency Fract" value={detail.currencyFract} />
      <Field label="PNR" value={detail.issuerPNR} />
      {detail.intercodeIssuing && <IntercodeIssuingSection data={detail.intercodeIssuing} />}
    </Section>
  );
}

function IntercodeIssuingSection({ data }: { data: IntercodeIssuingData }) {
  return (
    <div className="mt-2 pt-2 border-t border-gray-100">
      <h4 className="text-xs font-medium text-gray-400 mb-1">Intercode 6 Issuing</h4>
      <Field label="Version" value={data.intercodeVersion} />
      <Field label="Instanciation" value={data.intercodeInstanciation} />
      <BytesField label="Network ID" value={data.networkId} />
      {data.productRetailer && (
        <>
          <Field label="Retail Channel" value={data.productRetailer.retailChannel} />
          <Field label="Retailer ID" value={data.productRetailer.retailerId} />
          <Field label="Retail Point" value={data.productRetailer.retailPointId} />
          <Field label="Server ID" value={data.productRetailer.retailServerId} />
          <Field label="Generator ID" value={data.productRetailer.retailGeneratorId} />
        </>
      )}
    </div>
  );
}

function TravelerSection({ detail }: { detail: TravelerDetail }) {
  return (
    <Section title="Traveler Detail">
      <Field label="Language" value={detail.preferredLanguage} />
      <Field label="Group Name" value={detail.groupName} />
      {detail.traveler?.map((t, i) => (
        <div key={i} className="mt-1 pt-1 border-t border-gray-100">
          <span className="text-xs text-gray-400">Traveler {i + 1}</span>
          <Field label="First Name" value={t.firstName} />
          <Field label="Last Name" value={t.lastName} />
          <Field label="Date of Birth" value={t.dateOfBirth} />
          <Field label="Ticket Holder" value={t.ticketHolder} />
          <Field label="Passenger Type" value={t.passengerType} />
          <Field label="Customer ID" value={t.customerIdIA5 ?? t.customerIdNum} />
          <Field label="ID Card" value={t.idCard} />
        </div>
      ))}
    </Section>
  );
}

function TransportDocSection({ docs }: { docs: TransportDocumentEntry[] }) {
  return (
    <Section title="Transport Documents">
      {docs.map((doc, i) => (
        <div key={i} className={i > 0 ? 'mt-2 pt-2 border-t border-gray-100' : ''}>
          <Field label="Type" value={doc.ticketType} />
          <div className="mt-1">
            <JsonTree data={doc.ticket} label="data" />
          </div>
        </div>
      ))}
    </Section>
  );
}

function ControlSection({ detail }: { detail: ControlDetail }) {
  return (
    <Section title="Control Detail">
      <Field label="ID by Card" value={detail.identificationByCardReference ? 'Yes' : undefined} />
      <Field label="ID by ID Card" value={detail.identificationByIdCard} />
      <Field label="ID by Passport" value={detail.identificationByPassportId} />
      <Field label="Online Validation" value={detail.onlineValidationRequired} />
      <Field label="Age Check" value={detail.ageCheckRequired} />
      <Field label="Info Text" value={detail.infoText} />
      {detail.identificationByCardReference && (
        <JsonTree data={detail.identificationByCardReference} label="cardReferences" />
      )}
      {detail.includedTickets && (
        <JsonTree data={detail.includedTickets} label="includedTickets" />
      )}
    </Section>
  );
}

function DynamicDataSection({ data }: { data: IntercodeDynamicData }) {
  return (
    <Section title="Intercode 6 Dynamic Data">
      <Field label="Day" value={data.dynamicContentDay} />
      <Field label="Time" value={data.dynamicContentTime} />
      <Field label="UTC Offset" value={data.dynamicContentUTCOffset} />
      <Field label="Duration" value={data.dynamicContentDuration} />
    </Section>
  );
}

export default function TicketView({ ticket }: Props) {
  return (
    <div className="space-y-4">
      <Section title="Header">
        <Field label="Format" value={ticket.format} />
        <Field label="Header Version" value={ticket.headerVersion} />
      </Section>

      <SecuritySection security={ticket.security} />

      {ticket.railTickets.map((rt, i) => (
        <div key={i} className="space-y-4">
          <Section title={`Rail Ticket ${ticket.railTickets.length > 1 ? i + 1 : ''} (FCB${rt.fcbVersion})`}>
            <Field label="FCB Version" value={rt.fcbVersion} />
          </Section>

          {rt.issuingDetail && <IssuingSection detail={rt.issuingDetail} />}
          {rt.travelerDetail && <TravelerSection detail={rt.travelerDetail} />}
          {rt.transportDocument && rt.transportDocument.length > 0 && (
            <TransportDocSection docs={rt.transportDocument} />
          )}
          {rt.controlDetail && <ControlSection detail={rt.controlDetail} />}
        </div>
      ))}

      {ticket.dynamicData && <DynamicDataSection data={ticket.dynamicData} />}

      {ticket.otherDataBlocks.length > 0 && (
        <Section title="Other Data Blocks">
          {ticket.otherDataBlocks.map((block, i) => (
            <div key={i}>
              <Field label="Format" value={block.dataFormat} />
              <BytesField label="Data" value={block.data} />
            </div>
          ))}
        </Section>
      )}
    </div>
  );
}
