import type { UicBarcodeTicket, Level1Data, UicRailTicketData, IssuingDetail, IntercodeIssuingData, IntercodeDynamicData, UicDynamicContentData, TravelerDetail, TravelerInfo, CustomerStatus, TransportDocumentData, ControlDetail, DataSequenceEntry, Level2Data } from 'dosipas-ts';
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

function oidDisplay(oid?: string): string | undefined {
  if (!oid) return undefined;
  const name = OID_NAMES[oid];
  return name ? `${oid} (${name})` : oid;
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

function Level1DataSection({ l1 }: { l1: Level1Data }) {
  return (
    <Section title="level1Data">
      <Field label="securityProviderNum" value={l1.securityProviderNum} />
      <Field label="securityProviderIA5" value={l1.securityProviderIA5} />
      <Field label="keyId" value={l1.keyId} />
      <Field label="level1KeyAlg" value={oidDisplay(l1.level1KeyAlg)} />
      <Field label="level2KeyAlg" value={oidDisplay(l1.level2KeyAlg)} />
      <Field label="level1SigningAlg" value={oidDisplay(l1.level1SigningAlg)} />
      <Field label="level2SigningAlg" value={oidDisplay(l1.level2SigningAlg)} />
      <BytesField label="level2PublicKey" value={l1.level2PublicKey} />
      <Field label="endOfValidityYear" value={l1.endOfValidityYear} />
      <Field label="endOfValidityDay" value={l1.endOfValidityDay} />
      <Field label="endOfValidityTime" value={l1.endOfValidityTime} />
      <Field label="validityDuration" value={l1.validityDuration} />
    </Section>
  );
}

function IssuingSection({ detail }: { detail: IssuingDetail }) {
  return (
    <Section title="issuingDetail">
      <Field label="securityProviderNum" value={detail.securityProviderNum} />
      <Field label="securityProviderIA5" value={detail.securityProviderIA5} />
      <Field label="issuerNum" value={detail.issuerNum} />
      <Field label="issuerIA5" value={detail.issuerIA5} />
      <Field label="issuerName" value={detail.issuerName} />
      <Field label="issuingYear" value={detail.issuingYear} />
      <Field label="issuingDay" value={detail.issuingDay} />
      <Field label="issuingTime" value={detail.issuingTime} />
      <Field label="specimen" value={detail.specimen} />
      <Field label="securePaperTicket" value={detail.securePaperTicket} />
      <Field label="activated" value={detail.activated} />
      <Field label="currency" value={detail.currency} />
      <Field label="currencyFract" value={detail.currencyFract} />
      <Field label="issuerPNR" value={detail.issuerPNR} />
      <Field label="issuedOnTrainNum" value={detail.issuedOnTrainNum} />
      <Field label="issuedOnTrainIA5" value={detail.issuedOnTrainIA5} />
      <Field label="issuedOnLine" value={detail.issuedOnLine} />
      {detail.pointOfSale && (
        <div className="mt-1 pt-1 border-t border-gray-100">
          <span className="text-xs text-gray-400">pointOfSale</span>
          <Field label="geoUnit" value={detail.pointOfSale.geoUnit} />
          <Field label="coordinateSystem" value={detail.pointOfSale.coordinateSystem} />
          <Field label="hemisphereLongitude" value={detail.pointOfSale.hemisphereLongitude} />
          <Field label="hemisphereLatitude" value={detail.pointOfSale.hemisphereLatitude} />
          <Field label="longitude" value={detail.pointOfSale.longitude} />
          <Field label="latitude" value={detail.pointOfSale.latitude} />
          <Field label="accuracy" value={detail.pointOfSale.accuracy} />
        </div>
      )}
      {detail.extension && (
        <div className="mt-1 pt-1 border-t border-gray-100">
          <span className="text-xs text-gray-400">extension</span>
          <Field label="extensionId" value={detail.extension.extensionId} />
          <BytesField label="extensionData" value={detail.extension.extensionData} />
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
        intercodeIssuing
        <span className="font-mono ml-1 text-gray-500">{data.extensionId}</span>
      </h4>
      <Field label="intercodeVersion" value={data.intercodeVersion} />
      <Field label="intercodeInstanciation" value={data.intercodeInstanciation} />
      <BytesField label="networkId" value={data.networkId} />
      {data.productRetailer && (
        <>
          <Field label="retailChannel" value={data.productRetailer.retailChannel} />
          <Field label="retailerId" value={data.productRetailer.retailerId} />
          <Field label="retailPointId" value={data.productRetailer.retailPointId} />
          <Field label="retailServerId" value={data.productRetailer.retailServerId} />
          <Field label="retailGeneratorId" value={data.productRetailer.retailGeneratorId} />
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
        <span className="text-gray-500 min-w-32 shrink-0">status</span>
        <span className="text-gray-300 italic text-xs">not set</span>
      </div>
    );
  }
  return (
    <>
      {statuses.map((s, i) => (
        <div key={i} className="ml-2 mt-1 pt-1 border-t border-gray-50">
          <span className="text-xs text-gray-400">status[{i}]</span>
          <FullField label="statusProviderNum" value={s.statusProviderNum} />
          <FullField label="statusProviderIA5" value={s.statusProviderIA5} />
          <FullField label="customerStatus" value={s.customerStatus} />
          <FullField label="customerStatusDescr" value={s.customerStatusDescr} />
        </div>
      ))}
    </>
  );
}

function TravelerSection({ detail }: { detail: TravelerDetail }) {
  return (
    <Section title="travelerDetail">
      <FullField label="preferredLanguage" value={detail.preferredLanguage} />
      <FullField label="groupName" value={detail.groupName} />
      {detail.traveler?.map((t, i) => (
        <div key={i} className="mt-1 pt-1 border-t border-gray-100">
          <span className="text-xs text-gray-400">traveler[{i}]</span>
          <FullField label="firstName" value={t.firstName} />
          <FullField label="secondName" value={t.secondName} />
          <FullField label="lastName" value={t.lastName} />
          <FullField label="title" value={t.title} />
          <FullField label="gender" value={t.gender} />
          <FullField label="dateOfBirth" value={t.dateOfBirth} />
          <FullField label="yearOfBirth" value={t.yearOfBirth} />
          <FullField label="monthOfBirth" value={t.monthOfBirth} />
          <FullField label="dayOfBirth" value={t.dayOfBirth} />
          <FullField label="dayOfBirthInMonth" value={t.dayOfBirthInMonth} />
          <FullField label="idCard" value={t.idCard} />
          <FullField label="passportId" value={t.passportId} />
          <FullField label="customerIdIA5" value={t.customerIdIA5} />
          <FullField label="customerIdNum" value={t.customerIdNum} />
          <FullField label="ticketHolder" value={t.ticketHolder} />
          <FullField label="passengerType" value={t.passengerType} />
          <FullField label="passengerWithReducedMobility" value={t.passengerWithReducedMobility} />
          <FullField label="countryOfResidence" value={t.countryOfResidence} />
          <FullField label="countryOfPassport" value={t.countryOfPassport} />
          <FullField label="countryOfIdCard" value={t.countryOfIdCard} />
          <CustomerStatusSection statuses={t.status} />
        </div>
      ))}
    </Section>
  );
}

function TransportDocSection({ docs }: { docs: TransportDocumentData[] }) {
  return (
    <Section title="transportDocument">
      {docs.map((doc, i) => (
        <div key={i} className={i > 0 ? 'mt-2 pt-2 border-t border-gray-100' : ''}>
          <Field label="ticket (CHOICE)" value={doc.ticket.key} />
          <div className="mt-1">
            <JsonTree data={doc.ticket.value} label={doc.ticket.key} />
          </div>
        </div>
      ))}
    </Section>
  );
}

function ControlSection({ detail }: { detail: ControlDetail }) {
  return (
    <Section title="controlDetail">
      <Field label="identificationByCardReference" value={detail.identificationByCardReference ? 'present' : undefined} />
      <Field label="identificationByIdCard" value={detail.identificationByIdCard} />
      <Field label="identificationByPassportId" value={detail.identificationByPassportId} />
      <Field label="identificationItem" value={detail.identificationItem} />
      <Field label="passportValidationRequired" value={detail.passportValidationRequired} />
      <Field label="onlineValidationRequired" value={detail.onlineValidationRequired} />
      <Field label="randomDetailedValidationRequired" value={detail.randomDetailedValidationRequired} />
      <Field label="ageCheckRequired" value={detail.ageCheckRequired} />
      <Field label="reductionCardCheckRequired" value={detail.reductionCardCheckRequired} />
      <Field label="infoText" value={detail.infoText} />
      {detail.identificationByCardReference && (
        <JsonTree data={detail.identificationByCardReference} label="identificationByCardReference" />
      )}
      {detail.includedTickets && (
        <JsonTree data={detail.includedTickets} label="includedTickets" />
      )}
      {detail.extension && (
        <div className="mt-1 pt-1 border-t border-gray-100">
          <span className="text-xs text-gray-400">extension</span>
          <Field label="extensionId" value={detail.extension.extensionId} />
          <BytesField label="extensionData" value={detail.extension.extensionData} />
        </div>
      )}
    </Section>
  );
}

function IntercodeDynamicSection({ data, dataFormat }: { data: IntercodeDynamicData; dataFormat: string }) {
  return (
    <Section title="level2Data (IntercodeDynamicData)">
      <Field label="dataFormat" value={dataFormat} />
      <Field label="dynamicContentDay" value={data.dynamicContentDay} />
      <Field label="dynamicContentTime" value={data.dynamicContentTime} />
      <Field label="dynamicContentUTCOffset" value={data.dynamicContentUTCOffset} />
      <Field label="dynamicContentDuration" value={data.dynamicContentDuration} />
    </Section>
  );
}

function DynamicContentDataSection({ data, dataFormat }: { data: UicDynamicContentData; dataFormat: string }) {
  return (
    <Section title="level2Data (UicDynamicContentData)">
      <Field label="dataFormat" value={dataFormat} />
      <Field label="dynamicContentMobileAppId" value={data.dynamicContentMobileAppId} />
      {data.dynamicContentTimeStamp && (
        <div className="mt-1 pt-1 border-t border-gray-100">
          <span className="text-xs text-gray-400">dynamicContentTimeStamp</span>
          <Field label="day" value={data.dynamicContentTimeStamp.day} />
          <Field label="time" value={data.dynamicContentTimeStamp.time} />
        </div>
      )}
      {data.dynamicContentGeoCoordinate && (
        <div className="mt-1 pt-1 border-t border-gray-100">
          <span className="text-xs text-gray-400">dynamicContentGeoCoordinate</span>
          <Field label="geoUnit" value={data.dynamicContentGeoCoordinate.geoUnit} />
          <Field label="coordinateSystem" value={data.dynamicContentGeoCoordinate.coordinateSystem} />
          <Field label="hemisphereLongitude" value={data.dynamicContentGeoCoordinate.hemisphereLongitude} />
          <Field label="hemisphereLatitude" value={data.dynamicContentGeoCoordinate.hemisphereLatitude} />
          <Field label="longitude" value={data.dynamicContentGeoCoordinate.longitude} />
          <Field label="latitude" value={data.dynamicContentGeoCoordinate.latitude} />
          <Field label="accuracy" value={data.dynamicContentGeoCoordinate.accuracy} />
        </div>
      )}
      {data.dynamicContentResponseToChallenge && data.dynamicContentResponseToChallenge.length > 0 && (
        <div className="mt-1 pt-1 border-t border-gray-100">
          <span className="text-xs text-gray-400">dynamicContentResponseToChallenge</span>
          {data.dynamicContentResponseToChallenge.map((ext, i) => (
            <div key={i}>
              <Field label={`[${i}].extensionId`} value={ext.extensionId} />
              <BytesField label={`[${i}].extensionData`} value={ext.extensionData} />
            </div>
          ))}
        </div>
      )}
      {data.dynamicContentExtension && (
        <div className="mt-1 pt-1 border-t border-gray-100">
          <span className="text-xs text-gray-400">dynamicContentExtension</span>
          <Field label="extensionId" value={data.dynamicContentExtension.extensionId} />
          <BytesField label="extensionData" value={data.dynamicContentExtension.extensionData} />
        </div>
      )}
    </Section>
  );
}

function DecodedFcbSection({ entry, index }: { entry: DataSequenceEntry; index: number }) {
  const rt = entry.decoded;
  if (!rt) {
    return (
      <EmbeddedBlock label={`dataSequence[${index}] — ${entry.dataFormat}`}>
        <Section title={entry.dataFormat}>
          <BytesField label="data" value={entry.data} />
        </Section>
      </EmbeddedBlock>
    );
  }

  return (
    <EmbeddedBlock label={`dataSequence[${index}] — ${entry.dataFormat}`}>
      {rt.issuingDetail && <IssuingSection detail={rt.issuingDetail} />}
      {rt.travelerDetail && <TravelerSection detail={rt.travelerDetail} />}
      {rt.transportDocument && rt.transportDocument.length > 0 && (
        <TransportDocSection docs={rt.transportDocument} />
      )}
      {rt.controlDetail && <ControlSection detail={rt.controlDetail} />}
    </EmbeddedBlock>
  );
}

function Level2DataSection({ l2Data }: { l2Data: Level2Data }) {
  if (!l2Data.decoded) {
    return (
      <Section title="level2Data">
        <Field label="dataFormat" value={l2Data.dataFormat} />
        <BytesField label="data" value={l2Data.data} />
      </Section>
    );
  }

  // FDC1 = UicDynamicContentData
  if (l2Data.dataFormat === 'FDC1') {
    return <DynamicContentDataSection data={l2Data.decoded as UicDynamicContentData} dataFormat={l2Data.dataFormat} />;
  }

  // _RICS.ID1 = IntercodeDynamicData
  return <IntercodeDynamicSection data={l2Data.decoded as IntercodeDynamicData} dataFormat={l2Data.dataFormat} />;
}

export default function TicketView({ ticket }: Props) {
  const l2Signed = ticket.level2SignedData;
  const l1 = l2Signed.level1Data;

  return (
    <div className="space-y-4">
      {/* Header — outside both signature regions */}
      <Section title="UicBarcodeHeader">
        <Field label="format" value={ticket.format} />
      </Section>

      {/* Level 2 Signature Payload (level2SignedData) */}
      <SignatureRegion label="level2SignedData" color="green">
        {/* Level 1 Signature Payload (level1Data) */}
        <SignatureRegion label="level1Data" color="blue">
          <Level1DataSection l1={l1} />

          {/* dataSequence — decoded FCB blocks + other data blocks */}
          {l1.dataSequence.map((entry, i) => (
            <DecodedFcbSection key={i} entry={entry} index={i} />
          ))}
        </SignatureRegion>

        {/* level1Signature — inside level2SignedData, outside level1Data */}
        <Section title="level1Signature">
          <BytesField label="level1Signature" value={l2Signed.level1Signature} />
        </Section>

        {/* level2Data — inside level2SignedData, outside level1Data */}
        {l2Signed.level2Data && <Level2DataSection l2Data={l2Signed.level2Data} />}
      </SignatureRegion>

      {/* level2Signature — outside level2SignedData */}
      {ticket.level2Signature && (
        <Section title="level2Signature">
          <BytesField label="level2Signature" value={ticket.level2Signature} />
        </Section>
      )}
    </div>
  );
}
