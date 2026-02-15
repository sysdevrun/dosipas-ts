import type { UicBarcodeTicket, SecurityInfo, RailTicketData, IssuingDetail, IntercodeIssuingData, IntercodeDynamicData, UicDynamicContentData, TravelerDetail, TravelerInfo, CustomerStatus, TransportDocumentEntry, ControlDetail } from 'dosipas-ts';
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

/** Signature-payload region wrapper with colored left border and label. */
function SignatureRegion({
  label,
  color,
  children,
}: {
  label: string;
  color: 'green' | 'blue';
  children: React.ReactNode;
}) {
  const borderColor = color === 'green' ? 'border-green-400' : 'border-blue-400';
  const bgColor = color === 'green' ? 'bg-green-50' : 'bg-blue-50';
  const textColor = color === 'green' ? 'text-green-700' : 'text-blue-700';
  const badgeBg = color === 'green' ? 'bg-green-100' : 'bg-blue-100';

  return (
    <div className={`border-l-2 ${borderColor} ${bgColor} rounded-r-lg pl-3 pr-1 py-3 space-y-4`}>
      <div className="flex items-center gap-2">
        <span className={`text-xs font-semibold ${textColor} ${badgeBg} px-2 py-0.5 rounded`}>
          {label}
        </span>
      </div>
      {children}
    </div>
  );
}

/** Embedded-structure indicator for non-signature nesting (e.g. FCB inside dataSequence). */
function EmbeddedBlock({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="border-l-2 border-gray-300 pl-3 space-y-4">
      <span className="text-xs font-medium text-gray-400 bg-gray-100 px-2 py-0.5 rounded">
        {label}
      </span>
      {children}
    </div>
  );
}

function SecurityMetadataSection({ security }: { security: SecurityInfo }) {
  return (
    <Section title="Security Metadata">
      <Field label="Provider" value={security.securityProviderNum} />
      <Field label="Provider (IA5)" value={security.securityProviderIA5} />
      <Field label="Key ID" value={security.keyId} />
      <Field label="L1 Key Alg" value={oidName(security.level1KeyAlg)} />
      <Field label="L2 Key Alg" value={oidName(security.level2KeyAlg)} />
      <Field label="L1 Signing Alg" value={oidName(security.level1SigningAlg)} />
      <Field label="L2 Signing Alg" value={oidName(security.level2SigningAlg)} />
      <BytesField label="L2 Public Key" value={security.level2PublicKey} />
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
      <Field label="Issued on Train (num)" value={detail.issuedOnTrainNum} />
      <Field label="Issued on Train (IA5)" value={detail.issuedOnTrainIA5} />
      <Field label="Issued on Line" value={detail.issuedOnLine} />
      {detail.pointOfSale && (
        <div className="mt-1 pt-1 border-t border-gray-100">
          <span className="text-xs text-gray-400">Point of Sale</span>
          <Field label="Geo Unit" value={detail.pointOfSale.geoUnit} />
          <Field label="Coordinate System" value={detail.pointOfSale.coordinateSystem} />
          <Field label="Hemisphere Lon" value={detail.pointOfSale.hemisphereLongitude} />
          <Field label="Hemisphere Lat" value={detail.pointOfSale.hemisphereLatitude} />
          <Field label="Longitude" value={detail.pointOfSale.longitude} />
          <Field label="Latitude" value={detail.pointOfSale.latitude} />
          <Field label="Accuracy" value={detail.pointOfSale.accuracy} />
        </div>
      )}
      {detail.extension && (
        <div className="mt-1 pt-1 border-t border-gray-100">
          <span className="text-xs text-gray-400">Extension</span>
          <Field label="Extension ID" value={detail.extension.extensionId} />
          <BytesField label="Extension Data" value={detail.extension.extensionData} />
        </div>
      )}
      {detail.intercodeIssuing && <IntercodeIssuingSection data={detail.intercodeIssuing} />}
    </Section>
  );
}

function IntercodeIssuingSection({ data }: { data: IntercodeIssuingData }) {
  return (
    <div className="mt-2 pt-2 border-t border-gray-100">
      <h4 className="text-xs font-medium text-gray-400 mb-1">
        Intercode 6 Issuing
        <span className="font-mono ml-1 text-gray-500">{data.extensionId}</span>
      </h4>
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

function FullField({ label, value }: { label: string; value?: string | number | boolean | null }) {
  const isSet = value !== undefined && value !== null;
  return (
    <div className="flex gap-2 py-0.5">
      <span className="text-gray-500 min-w-32 shrink-0">{label}</span>
      {isSet ? (
        <span className="font-mono text-gray-900">
          {typeof value === 'boolean' ? (value ? 'Yes' : 'No') : String(value)}
        </span>
      ) : (
        <span className="text-gray-300 italic text-xs">not set</span>
      )}
    </div>
  );
}

function CustomerStatusSection({ statuses }: { statuses?: CustomerStatus[] }) {
  if (!statuses || statuses.length === 0) {
    return (
      <div className="flex gap-2 py-0.5">
        <span className="text-gray-500 min-w-32 shrink-0">Status</span>
        <span className="text-gray-300 italic text-xs">not set</span>
      </div>
    );
  }
  return (
    <>
      {statuses.map((s, i) => (
        <div key={i} className="ml-2 mt-1 pt-1 border-t border-gray-50">
          <span className="text-xs text-gray-400">Status {i + 1}</span>
          <FullField label="Provider (num)" value={s.statusProviderNum} />
          <FullField label="Provider (IA5)" value={s.statusProviderIA5} />
          <FullField label="Customer Status" value={s.customerStatus} />
          <FullField label="Status Descr." value={s.customerStatusDescr} />
        </div>
      ))}
    </>
  );
}

function TravelerSection({ detail }: { detail: TravelerDetail }) {
  return (
    <Section title="Traveler Detail">
      <FullField label="Language" value={detail.preferredLanguage} />
      <FullField label="Group Name" value={detail.groupName} />
      {detail.traveler?.map((t, i) => (
        <div key={i} className="mt-1 pt-1 border-t border-gray-100">
          <span className="text-xs text-gray-400">Traveler {i + 1}</span>
          <FullField label="First Name" value={t.firstName} />
          <FullField label="Second Name" value={t.secondName} />
          <FullField label="Last Name" value={t.lastName} />
          <FullField label="Title" value={t.title} />
          <FullField label="Gender" value={t.gender} />
          <FullField label="Date of Birth" value={t.dateOfBirth} />
          <FullField label="Year of Birth" value={t.yearOfBirth} />
          <FullField label="Month of Birth" value={t.monthOfBirth} />
          <FullField label="Day of Birth (v1)" value={t.dayOfBirth} />
          <FullField label="Day of Birth in Month (v2/v3)" value={t.dayOfBirthInMonth} />
          <FullField label="ID Card" value={t.idCard} />
          <FullField label="Passport ID" value={t.passportId} />
          <FullField label="Customer ID (IA5)" value={t.customerIdIA5} />
          <FullField label="Customer ID (num)" value={t.customerIdNum} />
          <FullField label="Ticket Holder" value={t.ticketHolder} />
          <FullField label="Passenger Type" value={t.passengerType} />
          <FullField label="Reduced Mobility" value={t.passengerWithReducedMobility} />
          <FullField label="Country of Residence" value={t.countryOfResidence} />
          <FullField label="Country of Passport" value={t.countryOfPassport} />
          <FullField label="Country of ID Card" value={t.countryOfIdCard} />
          <CustomerStatusSection statuses={t.status} />
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
      <Field label="Identification Item" value={detail.identificationItem} />
      <Field label="Passport Validation" value={detail.passportValidationRequired} />
      <Field label="Online Validation" value={detail.onlineValidationRequired} />
      <Field label="Random Detailed Validation" value={detail.randomDetailedValidationRequired} />
      <Field label="Age Check" value={detail.ageCheckRequired} />
      <Field label="Reduction Card Check" value={detail.reductionCardCheckRequired} />
      <Field label="Info Text" value={detail.infoText} />
      {detail.identificationByCardReference && (
        <JsonTree data={detail.identificationByCardReference} label="cardReferences" />
      )}
      {detail.includedTickets && (
        <JsonTree data={detail.includedTickets} label="includedTickets" />
      )}
      {detail.extension && (
        <div className="mt-1 pt-1 border-t border-gray-100">
          <span className="text-xs text-gray-400">Extension</span>
          <Field label="Extension ID" value={detail.extension.extensionId} />
          <BytesField label="Extension Data" value={detail.extension.extensionData} />
        </div>
      )}
    </Section>
  );
}

function DynamicDataSection({ data, dataFormat }: { data: IntercodeDynamicData; dataFormat?: string }) {
  return (
    <Section title="Level 2 Data — Intercode 6 Dynamic">
      <Field label="Data Format" value={dataFormat} />
      <Field label="Day" value={data.dynamicContentDay} />
      <Field label="Time" value={data.dynamicContentTime} />
      <Field label="UTC Offset" value={data.dynamicContentUTCOffset} />
      <Field label="Duration" value={data.dynamicContentDuration} />
    </Section>
  );
}

function DynamicContentDataSection({ data }: { data: UicDynamicContentData }) {
  return (
    <Section title="Level 2 Data — FDC1 Dynamic Content">
      <Field label="Mobile App ID" value={data.dynamicContentMobileAppId} />
      {data.dynamicContentTimeStamp && (
        <div className="mt-1 pt-1 border-t border-gray-100">
          <span className="text-xs text-gray-400">Timestamp (UTC)</span>
          <Field label="Day" value={data.dynamicContentTimeStamp.day} />
          <Field label="Time" value={data.dynamicContentTimeStamp.time} />
        </div>
      )}
      {data.dynamicContentGeoCoordinate && (
        <div className="mt-1 pt-1 border-t border-gray-100">
          <span className="text-xs text-gray-400">Geo Coordinate</span>
          <Field label="Geo Unit" value={data.dynamicContentGeoCoordinate.geoUnit} />
          <Field label="Coordinate System" value={data.dynamicContentGeoCoordinate.coordinateSystem} />
          <Field label="Hemisphere Lon" value={data.dynamicContentGeoCoordinate.hemisphereLongitude} />
          <Field label="Hemisphere Lat" value={data.dynamicContentGeoCoordinate.hemisphereLatitude} />
          <Field label="Longitude" value={data.dynamicContentGeoCoordinate.longitude} />
          <Field label="Latitude" value={data.dynamicContentGeoCoordinate.latitude} />
          <Field label="Accuracy" value={data.dynamicContentGeoCoordinate.accuracy} />
        </div>
      )}
      {data.dynamicContentResponseToChallenge && data.dynamicContentResponseToChallenge.length > 0 && (
        <div className="mt-1 pt-1 border-t border-gray-100">
          <span className="text-xs text-gray-400">Challenge Responses</span>
          {data.dynamicContentResponseToChallenge.map((ext, i) => (
            <div key={i}>
              <Field label={`[${i}] ID`} value={ext.extensionId} />
              <BytesField label={`[${i}] Data`} value={ext.extensionData} />
            </div>
          ))}
        </div>
      )}
      {data.dynamicContentExtension && (
        <div className="mt-1 pt-1 border-t border-gray-100">
          <span className="text-xs text-gray-400">Extension</span>
          <Field label="Extension ID" value={data.dynamicContentExtension.extensionId} />
          <BytesField label="Extension Data" value={data.dynamicContentExtension.extensionData} />
        </div>
      )}
    </Section>
  );
}

export default function TicketView({ ticket }: Props) {
  return (
    <div className="space-y-4">
      {/* Header — outside both signature regions */}
      <Section title="Header">
        <Field label="Format" value={ticket.format} />
        <Field label="Header Version" value={ticket.headerVersion} />
      </Section>

      {/* Level 2 Signature Payload (level2SignedData) */}
      <SignatureRegion label="Level 2 Signature Payload" color="green">
        {/* Level 1 Signature Payload (level1Data) */}
        <SignatureRegion label="Level 1 Signature Payload" color="blue">
          <SecurityMetadataSection security={ticket.security} />

          {/* dataSequence — decoded into rail tickets and other data blocks */}
          {ticket.railTickets.map((rt, i) => (
            <EmbeddedBlock
              key={i}
              label={`dataSequence[${i}] — FCB${rt.fcbVersion}`}
            >
              <Section title={`Rail Ticket ${ticket.railTickets.length > 1 ? i + 1 : ''} (FCB${rt.fcbVersion})`}>
                <Field label="FCB Version" value={rt.fcbVersion} />
              </Section>

              {rt.issuingDetail && <IssuingSection detail={rt.issuingDetail} />}
              {rt.travelerDetail && <TravelerSection detail={rt.travelerDetail} />}
              {rt.transportDocument && rt.transportDocument.length > 0 && (
                <TransportDocSection docs={rt.transportDocument} />
              )}
              {rt.controlDetail && <ControlSection detail={rt.controlDetail} />}
            </EmbeddedBlock>
          ))}

          {ticket.otherDataBlocks.length > 0 && (
            <EmbeddedBlock label={`dataSequence — other blocks`}>
              <Section title="Other Data Blocks">
                {ticket.otherDataBlocks.map((block, i) => (
                  <div key={i}>
                    <Field label="Format" value={block.dataFormat} />
                    <BytesField label="Data" value={block.data} />
                  </div>
                ))}
              </Section>
            </EmbeddedBlock>
          )}
        </SignatureRegion>

        {/* level1Signature — inside level2SignedData, outside level1Data */}
        <Section title="Level 1 Signature">
          <BytesField label="Signature" value={ticket.security.level1Signature} />
        </Section>

        {/* level2Data — inside level2SignedData, outside level1Data */}
        {ticket.dynamicData && <DynamicDataSection data={ticket.dynamicData} dataFormat={ticket.level2DataBlock?.dataFormat} />}
        {ticket.dynamicContentData && <DynamicContentDataSection data={ticket.dynamicContentData} />}
      </SignatureRegion>

      {/* level2Signature — outside level2SignedData */}
      {ticket.level2Signature && (
        <Section title="Level 2 Signature">
          <BytesField label="Signature" value={ticket.level2Signature} />
        </Section>
      )}
    </div>
  );
}
