import type {
  UicBarcodeTicketInput,
  IssuingDetailInput,
  IntercodeIssuingDataInput,
  TravelerDetailInput,
  TransportDocumentInput,
  RetailChannel,
} from 'dosipas-ts';

interface Props {
  value: UicBarcodeTicketInput;
  onChange: (input: UicBarcodeTicketInput) => void;
  renderAfterKeyId?: React.ReactNode;
  renderAfterValidityFields?: React.ReactNode;
  renderAfterIssuingFields?: React.ReactNode;
}

// ---------------------------------------------------------------------------
// Reusable field primitives (exported for use in EncodeTab)
// ---------------------------------------------------------------------------

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="space-y-2">
      <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wide">{title}</h4>
      <div className="grid grid-cols-2 gap-x-4 gap-y-2">{children}</div>
    </div>
  );
}

export function ToggleSection({
  title,
  enabled,
  onToggle,
  children,
}: {
  title: string;
  enabled: boolean;
  onToggle: (v: boolean) => void;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-2">
      <label className="flex items-center gap-2">
        <input
          type="checkbox"
          checked={enabled}
          onChange={(e) => onToggle(e.target.checked)}
          className="rounded border-gray-300"
        />
        <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wide">{title}</h4>
      </label>
      {enabled && <div className="grid grid-cols-2 gap-x-4 gap-y-2">{children}</div>}
    </div>
  );
}

export function NumberField({
  label,
  value,
  onChange,
  placeholder,
}: {
  label: string;
  value: number | undefined;
  onChange: (v: number | undefined) => void;
  placeholder?: string;
}) {
  return (
    <div>
      <label className="text-xs text-gray-500">{label}</label>
      <input
        type="number"
        value={value ?? ''}
        onChange={(e) => onChange(e.target.value ? Number(e.target.value) : undefined)}
        placeholder={placeholder}
        className="w-full mt-0.5 px-2 py-1 text-xs border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-400"
      />
    </div>
  );
}

export function OptionalNumberField({
  label,
  value,
  onChange,
  placeholder,
  defaultValue,
}: {
  label: string;
  value: number | undefined;
  onChange: (v: number | undefined) => void;
  placeholder?: string;
  defaultValue?: number;
}) {
  const enabled = value !== undefined;
  return (
    <div>
      <label className="flex items-center gap-1.5 text-xs text-gray-500">
        <input
          type="checkbox"
          checked={enabled}
          onChange={(e) => onChange(e.target.checked ? (defaultValue ?? 0) : undefined)}
          className="rounded border-gray-300"
        />
        {label}
      </label>
      {enabled && (
        <input
          type="number"
          value={value ?? ''}
          onChange={(e) => onChange(e.target.value ? Number(e.target.value) : undefined)}
          placeholder={placeholder}
          className="w-full mt-0.5 px-2 py-1 text-xs border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-400"
        />
      )}
    </div>
  );
}

function TextField({
  label,
  value,
  onChange,
  placeholder,
}: {
  label: string;
  value: string | undefined;
  onChange: (v: string | undefined) => void;
  placeholder?: string;
}) {
  return (
    <div>
      <label className="text-xs text-gray-500">{label}</label>
      <input
        type="text"
        value={value ?? ''}
        onChange={(e) => onChange(e.target.value || undefined)}
        placeholder={placeholder}
        className="w-full mt-0.5 px-2 py-1 text-xs border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-400"
      />
    </div>
  );
}

function OptionalTextField({
  label,
  value,
  onChange,
  placeholder,
}: {
  label: string;
  value: string | undefined;
  onChange: (v: string | undefined) => void;
  placeholder?: string;
}) {
  const enabled = value !== undefined;
  return (
    <div>
      <label className="flex items-center gap-1.5 text-xs text-gray-500">
        <input
          type="checkbox"
          checked={enabled}
          onChange={(e) => onChange(e.target.checked ? '' : undefined)}
          className="rounded border-gray-300"
        />
        {label}
      </label>
      {enabled && (
        <input
          type="text"
          value={value ?? ''}
          onChange={(e) => onChange(e.target.value || undefined)}
          placeholder={placeholder}
          className="w-full mt-0.5 px-2 py-1 text-xs border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-400"
        />
      )}
    </div>
  );
}

function CheckboxField({
  label,
  value,
  onChange,
}: {
  label: string;
  value: boolean | undefined;
  onChange: (v: boolean) => void;
}) {
  return (
    <label className="flex items-center gap-2 text-xs text-gray-700 cursor-pointer">
      <input
        type="checkbox"
        checked={value ?? false}
        onChange={(e) => onChange(e.target.checked)}
        className="rounded border-gray-300"
      />
      {label}
    </label>
  );
}

function SelectField({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: number | undefined;
  options: { label: string; value: number }[];
  onChange: (v: number) => void;
}) {
  return (
    <div>
      <label className="text-xs text-gray-500">{label}</label>
      <select
        value={value ?? options[0]?.value}
        onChange={(e) => onChange(Number(e.target.value))}
        className="w-full mt-0.5 px-2 py-1 text-xs border border-gray-300 rounded bg-white focus:outline-none focus:ring-2 focus:ring-blue-400"
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>
    </div>
  );
}

function StringSelectField({
  label,
  value,
  options,
  onChange,
  allowEmpty,
}: {
  label: string;
  value: string | undefined;
  options: { label: string; value: string }[];
  onChange: (v: string | undefined) => void;
  allowEmpty?: boolean;
}) {
  return (
    <div>
      <label className="text-xs text-gray-500">{label}</label>
      <select
        value={value ?? ''}
        onChange={(e) => onChange(e.target.value || undefined)}
        className="w-full mt-0.5 px-2 py-1 text-xs border border-gray-300 rounded bg-white focus:outline-none focus:ring-2 focus:ring-blue-400"
      >
        {allowEmpty && <option value="">-- none --</option>}
        {options.map((o) => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>
    </div>
  );
}

function BytesHexField({
  label,
  value,
  onChange,
  placeholder,
}: {
  label: string;
  value: Uint8Array | undefined;
  onChange: (v: Uint8Array) => void;
  placeholder?: string;
}) {
  const hex = value ? Array.from(value).map((b) => b.toString(16).padStart(2, '0')).join('') : '';
  return (
    <div>
      <label className="text-xs text-gray-500">{label}</label>
      <input
        type="text"
        value={hex}
        onChange={(e) => {
          const clean = e.target.value.replace(/[^0-9a-fA-F]/g, '');
          const bytes = new Uint8Array(Math.floor(clean.length / 2));
          for (let i = 0; i < bytes.length; i++) {
            bytes[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16);
          }
          onChange(bytes);
        }}
        placeholder={placeholder}
        className="w-full mt-0.5 px-2 py-1 text-xs font-mono border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-400"
        spellCheck={false}
      />
    </div>
  );
}

function JsonField({
  label,
  value,
  onChange,
}: {
  label: string;
  value: unknown;
  onChange: (v: unknown) => void;
}) {
  const text = JSON.stringify(value ?? null, null, 2);
  return (
    <div className="col-span-2">
      <label className="text-xs text-gray-500">{label}</label>
      <textarea
        value={text}
        onChange={(e) => {
          try { onChange(JSON.parse(e.target.value)); } catch { /* ignore parse errors while typing */ }
        }}
        className="w-full mt-0.5 px-2 py-1 text-xs font-mono border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-400 h-24 resize-y"
        spellCheck={false}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Retail channel options
// ---------------------------------------------------------------------------

const RETAIL_CHANNELS = [
  { label: 'SMS Ticket', value: 'smsTicket' },
  { label: 'Mobile App', value: 'mobileApplication' },
  { label: 'Website', value: 'webSite' },
  { label: 'Ticket Office', value: 'ticketOffice' },
  { label: 'Depositary Terminal', value: 'depositaryTerminal' },
  { label: 'On-board Terminal', value: 'onBoardTerminal' },
  { label: 'Vending Machine', value: 'ticketVendingMachine' },
];

// ---------------------------------------------------------------------------
// Main form component (Level 1 data only)
// ---------------------------------------------------------------------------

export default function TicketForm({
  value,
  onChange,
  renderAfterKeyId,
  renderAfterValidityFields,
  renderAfterIssuingFields,
}: Props) {
  const update = (partial: Partial<UicBarcodeTicketInput>) => {
    onChange({ ...value, ...partial });
  };

  const updateIssuing = (partial: Partial<IssuingDetailInput>) => {
    onChange({
      ...value,
      railTicket: {
        ...value.railTicket,
        issuingDetail: { ...value.railTicket.issuingDetail, ...partial },
      },
    });
  };

  const updateIntercodeIssuing = (partial: Partial<IntercodeIssuingDataInput>) => {
    const current = value.railTicket.issuingDetail.intercodeIssuing;
    if (!current) return;
    updateIssuing({
      intercodeIssuing: { ...current, ...partial },
    });
  };

  const updateTraveler = (partial: Partial<TravelerDetailInput>) => {
    onChange({
      ...value,
      railTicket: {
        ...value.railTicket,
        travelerDetail: { ...value.railTicket.travelerDetail, ...partial },
      },
    });
  };

  const now = new Date();
  const dayOfYear = Math.floor(
    (now.getTime() - new Date(now.getFullYear(), 0, 0).getTime()) / 86400000,
  );

  const hasTraveler = !!value.railTicket.travelerDetail;
  const hasIntercode = !!value.railTicket.issuingDetail.intercodeIssuing;
  const hasControl = !!value.railTicket.controlDetail;

  const traveler = value.railTicket.travelerDetail?.traveler?.[0];

  const updateTravelerPerson = (partial: Record<string, unknown>) => {
    const current = value.railTicket.travelerDetail?.traveler?.[0] ?? {};
    onChange({
      ...value,
      railTicket: {
        ...value.railTicket,
        travelerDetail: {
          ...value.railTicket.travelerDetail,
          traveler: [{ ...current, ...partial }],
        },
      },
    });
  };

  return (
    <div className="space-y-4">
      {/* UicBarcodeHeader */}
      <Section title="UicBarcodeHeader">
        <SelectField
          label="headerVersion"
          value={value.headerVersion}
          options={[
            { label: 'v2', value: 2 },
            { label: 'v1', value: 1 },
          ]}
          onChange={(v) => update({ headerVersion: v })}
        />
        <SelectField
          label="fcbVersion"
          value={value.fcbVersion}
          options={[
            { label: 'FCB3', value: 3 },
            { label: 'FCB2', value: 2 },
            { label: 'FCB1', value: 1 },
          ]}
          onChange={(v) => update({ fcbVersion: v })}
        />
      </Section>

      {/* level1Data */}
      <Section title="level1Data">
        <NumberField
          label="securityProviderNum"
          value={value.securityProviderNum}
          onChange={(v) => update({ securityProviderNum: v })}
          placeholder="e.g. 1187"
        />
        <NumberField
          label="keyId"
          value={value.keyId}
          onChange={(v) => update({ keyId: v })}
          placeholder="e.g. 1"
        />
        {renderAfterKeyId}
        <OptionalNumberField
          label="endOfValidityYear"
          value={value.endOfValidityYear}
          onChange={(v) => update({ endOfValidityYear: v })}
          placeholder="2016-2269"
          defaultValue={now.getFullYear()}
        />
        <OptionalNumberField
          label="endOfValidityDay"
          value={value.endOfValidityDay}
          onChange={(v) => update({ endOfValidityDay: v })}
          placeholder="1-366"
          defaultValue={dayOfYear}
        />
        <OptionalNumberField
          label="endOfValidityTime"
          value={value.endOfValidityTime}
          onChange={(v) => update({ endOfValidityTime: v })}
          placeholder="0-1439 (minutes)"
        />
        <OptionalNumberField
          label="validityDuration"
          value={value.validityDuration}
          onChange={(v) => update({ validityDuration: v })}
          placeholder="1-3600 (seconds)"
        />
        {renderAfterValidityFields}
      </Section>

      {/* issuingDetail */}
      <Section title="issuingDetail">
        <OptionalNumberField
          label="securityProviderNum"
          value={value.railTicket.issuingDetail.securityProviderNum}
          onChange={(v) => updateIssuing({ securityProviderNum: v })}
          placeholder="e.g. 1187"
        />
        <OptionalNumberField
          label="issuerNum"
          value={value.railTicket.issuingDetail.issuerNum}
          onChange={(v) => updateIssuing({ issuerNum: v })}
          placeholder="e.g. 1187"
        />
        <NumberField
          label="issuingYear"
          value={value.railTicket.issuingDetail.issuingYear}
          onChange={(v) => updateIssuing({ issuingYear: v ?? now.getFullYear() })}
          placeholder={String(now.getFullYear())}
        />
        <NumberField
          label="issuingDay"
          value={value.railTicket.issuingDetail.issuingDay}
          onChange={(v) => updateIssuing({ issuingDay: v ?? dayOfYear })}
          placeholder={String(dayOfYear)}
        />
        <OptionalNumberField
          label="issuingTime"
          value={value.railTicket.issuingDetail.issuingTime}
          onChange={(v) => updateIssuing({ issuingTime: v })}
          placeholder="Minutes since midnight"
        />
        <OptionalTextField
          label="issuerName"
          value={value.railTicket.issuingDetail.issuerName}
          onChange={(v) => updateIssuing({ issuerName: v })}
          placeholder="e.g. SNCF"
        />
        <OptionalTextField
          label="currency"
          value={value.railTicket.issuingDetail.currency}
          onChange={(v) => updateIssuing({ currency: v })}
          placeholder="EUR"
        />
        <OptionalNumberField
          label="currencyFract"
          value={value.railTicket.issuingDetail.currencyFract}
          onChange={(v) => updateIssuing({ currencyFract: v })}
          placeholder="e.g. 2"
        />
        <OptionalTextField
          label="issuerPNR"
          value={value.railTicket.issuingDetail.issuerPNR}
          onChange={(v) => updateIssuing({ issuerPNR: v })}
        />
        <div className="col-span-2 flex gap-4">
          <CheckboxField
            label="specimen"
            value={value.railTicket.issuingDetail.specimen}
            onChange={(v) => updateIssuing({ specimen: v })}
          />
          <CheckboxField
            label="securePaperTicket"
            value={value.railTicket.issuingDetail.securePaperTicket}
            onChange={(v) => updateIssuing({ securePaperTicket: v })}
          />
          <CheckboxField
            label="activated"
            value={value.railTicket.issuingDetail.activated}
            onChange={(v) => updateIssuing({ activated: v })}
          />
        </div>
        {renderAfterIssuingFields}
      </Section>

      {/* intercodeIssuing */}
      <ToggleSection
        title="intercodeIssuing"
        enabled={hasIntercode}
        onToggle={(v) => {
          if (v) {
            updateIssuing({
              intercodeIssuing: {
                intercodeVersion: 1,
                intercodeInstanciation: 1,
                networkId: new Uint8Array([0x00, 0x00]),
              },
            });
          } else {
            updateIssuing({ intercodeIssuing: undefined });
          }
        }}
      >
        {/* Extension ID format selector */}
        {(() => {
          const extId = value.railTicket.issuingDetail.intercodeIssuing?.extensionId;
          const isCountryCode = extId ? /^\+[A-Z]{2}II1$/.test(extId) : false;
          const countryCode = isCountryCode && extId ? extId.slice(1, 3) : '';
          return (
            <div className="col-span-2 flex items-center gap-3 mb-1">
              <span className="text-xs text-gray-500">Extension ID</span>
              <label className="flex items-center gap-1">
                <input
                  type="radio"
                  name="extensionIdFormat"
                  checked={!isCountryCode}
                  onChange={() => updateIntercodeIssuing({ extensionId: undefined })}
                  className="text-blue-600"
                />
                <span className="text-xs text-gray-700">_RICS II1</span>
              </label>
              <label className="flex items-center gap-1">
                <input
                  type="radio"
                  name="extensionIdFormat"
                  checked={isCountryCode}
                  onChange={() => updateIntercodeIssuing({ extensionId: '+FRII1' })}
                  className="text-blue-600"
                />
                <span className="text-xs text-gray-700">+CC II1</span>
              </label>
              {isCountryCode && (
                <input
                  type="text"
                  value={countryCode}
                  maxLength={2}
                  onChange={(e) => {
                    const cc = e.target.value.toUpperCase().replace(/[^A-Z]/g, '');
                    updateIntercodeIssuing({ extensionId: cc.length === 2 ? `+${cc}II1` : extId });
                  }}
                  placeholder="FR"
                  className="w-12 px-1 py-0.5 text-xs font-mono border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-400 uppercase"
                />
              )}
            </div>
          );
        })()}
        <NumberField
          label="intercodeVersion"
          value={value.railTicket.issuingDetail.intercodeIssuing?.intercodeVersion}
          onChange={(v) => updateIntercodeIssuing({ intercodeVersion: v ?? 1 })}
        />
        <NumberField
          label="intercodeInstanciation"
          value={value.railTicket.issuingDetail.intercodeIssuing?.intercodeInstanciation}
          onChange={(v) => updateIntercodeIssuing({ intercodeInstanciation: v ?? 1 })}
        />
        <BytesHexField
          label="networkId"
          value={value.railTicket.issuingDetail.intercodeIssuing?.networkId}
          onChange={(v) => updateIntercodeIssuing({ networkId: v })}
          placeholder="e.g. 0087"
        />
        <div /> {/* spacer */}

        {/* productRetailer sub-section */}
        <div className="col-span-2 mt-1 pt-1 border-t border-gray-100">
          <span className="text-xs text-gray-400">productRetailer</span>
        </div>
        <StringSelectField
          label="retailChannel"
          value={value.railTicket.issuingDetail.intercodeIssuing?.productRetailer?.retailChannel}
          options={RETAIL_CHANNELS}
          onChange={(v) =>
            updateIntercodeIssuing({
              productRetailer: {
                ...value.railTicket.issuingDetail.intercodeIssuing?.productRetailer,
                retailChannel: v as RetailChannel | undefined,
              },
            })
          }
          allowEmpty
        />
        <OptionalNumberField
          label="retailGeneratorId"
          value={value.railTicket.issuingDetail.intercodeIssuing?.productRetailer?.retailGeneratorId}
          onChange={(v) =>
            updateIntercodeIssuing({
              productRetailer: {
                ...value.railTicket.issuingDetail.intercodeIssuing?.productRetailer,
                retailGeneratorId: v,
              },
            })
          }
        />
        <OptionalNumberField
          label="retailServerId"
          value={value.railTicket.issuingDetail.intercodeIssuing?.productRetailer?.retailServerId}
          onChange={(v) =>
            updateIntercodeIssuing({
              productRetailer: {
                ...value.railTicket.issuingDetail.intercodeIssuing?.productRetailer,
                retailServerId: v,
              },
            })
          }
        />
        <OptionalNumberField
          label="retailerId"
          value={value.railTicket.issuingDetail.intercodeIssuing?.productRetailer?.retailerId}
          onChange={(v) =>
            updateIntercodeIssuing({
              productRetailer: {
                ...value.railTicket.issuingDetail.intercodeIssuing?.productRetailer,
                retailerId: v,
              },
            })
          }
        />
        <OptionalNumberField
          label="retailPointId"
          value={value.railTicket.issuingDetail.intercodeIssuing?.productRetailer?.retailPointId}
          onChange={(v) =>
            updateIntercodeIssuing({
              productRetailer: {
                ...value.railTicket.issuingDetail.intercodeIssuing?.productRetailer,
                retailPointId: v,
              },
            })
          }
        />
      </ToggleSection>

      {/* travelerDetail */}
      <ToggleSection
        title="travelerDetail"
        enabled={hasTraveler}
        onToggle={(v) => {
          onChange({
            ...value,
            railTicket: {
              ...value.railTicket,
              travelerDetail: v ? { traveler: [{}] } : undefined,
            },
          });
        }}
      >
        <OptionalTextField
          label="preferredLanguage"
          value={value.railTicket.travelerDetail?.preferredLanguage}
          onChange={(v) => updateTraveler({ preferredLanguage: v })}
          placeholder="e.g. EN"
        />
        <OptionalTextField
          label="groupName"
          value={value.railTicket.travelerDetail?.groupName}
          onChange={(v) => updateTraveler({ groupName: v })}
        />

        <div className="col-span-2 mt-1 pt-1 border-t border-gray-100">
          <span className="text-xs text-gray-400">traveler[0]</span>
        </div>

        <OptionalTextField
          label="firstName"
          value={traveler?.firstName}
          onChange={(v) => updateTravelerPerson({ firstName: v })}
        />
        <OptionalTextField
          label="secondName"
          value={traveler?.secondName}
          onChange={(v) => updateTravelerPerson({ secondName: v })}
        />
        <OptionalTextField
          label="lastName"
          value={traveler?.lastName}
          onChange={(v) => updateTravelerPerson({ lastName: v })}
        />
        <OptionalTextField
          label="title"
          value={traveler?.title}
          onChange={(v) => updateTravelerPerson({ title: v })}
        />
        <StringSelectField
          label="gender"
          value={traveler?.gender}
          options={[
            { label: 'male', value: 'male' },
            { label: 'female', value: 'female' },
            { label: 'other', value: 'other' },
          ]}
          onChange={(v) => updateTravelerPerson({ gender: v })}
          allowEmpty
        />
        <OptionalTextField
          label="idCard"
          value={traveler?.idCard}
          onChange={(v) => updateTravelerPerson({ idCard: v })}
        />
        <OptionalTextField
          label="passportId"
          value={traveler?.passportId}
          onChange={(v) => updateTravelerPerson({ passportId: v })}
        />
        <OptionalTextField
          label="customerIdIA5"
          value={traveler?.customerIdIA5}
          onChange={(v) => updateTravelerPerson({ customerIdIA5: v })}
        />
        <OptionalNumberField
          label="customerIdNum"
          value={traveler?.customerIdNum}
          onChange={(v) => updateTravelerPerson({ customerIdNum: v })}
        />
        <OptionalNumberField
          label="yearOfBirth"
          value={traveler?.yearOfBirth}
          onChange={(v) => updateTravelerPerson({ yearOfBirth: v })}
          placeholder="e.g. 1990"
        />
        <OptionalNumberField
          label="monthOfBirth"
          value={traveler?.monthOfBirth}
          onChange={(v) => updateTravelerPerson({ monthOfBirth: v })}
          placeholder="1-12"
        />
        <OptionalNumberField
          label="dayOfBirth"
          value={traveler?.dayOfBirth}
          onChange={(v) => updateTravelerPerson({ dayOfBirth: v })}
          placeholder="0-370 (day of year)"
        />
        <OptionalNumberField
          label="dayOfBirthInMonth"
          value={traveler?.dayOfBirthInMonth}
          onChange={(v) => updateTravelerPerson({ dayOfBirthInMonth: v })}
          placeholder="1-31"
        />
        <CheckboxField
          label="ticketHolder"
          value={traveler?.ticketHolder}
          onChange={(v) => updateTravelerPerson({ ticketHolder: v })}
        />
        <OptionalTextField
          label="passengerType"
          value={traveler?.passengerType as string | undefined}
          onChange={(v) => updateTravelerPerson({ passengerType: v })}
        />
        <CheckboxField
          label="passengerWithReducedMobility"
          value={traveler?.passengerWithReducedMobility}
          onChange={(v) => updateTravelerPerson({ passengerWithReducedMobility: v })}
        />
        <OptionalNumberField
          label="countryOfResidence"
          value={traveler?.countryOfResidence}
          onChange={(v) => updateTravelerPerson({ countryOfResidence: v })}
        />
        <OptionalNumberField
          label="countryOfPassport"
          value={traveler?.countryOfPassport}
          onChange={(v) => updateTravelerPerson({ countryOfPassport: v })}
        />
        <OptionalNumberField
          label="countryOfIdCard"
          value={traveler?.countryOfIdCard}
          onChange={(v) => updateTravelerPerson({ countryOfIdCard: v })}
        />
      </ToggleSection>

      {/* transportDocument */}
      <Section title="transportDocument">
        <JsonField
          label="transportDocument"
          value={value.railTicket.transportDocument}
          onChange={(v) =>
            onChange({
              ...value,
              railTicket: { ...value.railTicket, transportDocument: v as TransportDocumentInput[] | undefined },
            })
          }
        />
      </Section>

      {/* controlDetail */}
      <ToggleSection
        title="controlDetail"
        enabled={hasControl}
        onToggle={(v) => {
          onChange({
            ...value,
            railTicket: {
              ...value.railTicket,
              controlDetail: v ? {} : undefined,
            },
          });
        }}
      >
        <CheckboxField
          label="identificationByIdCard"
          value={(value.railTicket.controlDetail as Record<string, unknown> | undefined)?.identificationByIdCard as boolean | undefined}
          onChange={(v) =>
            onChange({
              ...value,
              railTicket: {
                ...value.railTicket,
                controlDetail: { ...value.railTicket.controlDetail, identificationByIdCard: v },
              },
            })
          }
        />
        <CheckboxField
          label="identificationByPassportId"
          value={(value.railTicket.controlDetail as Record<string, unknown> | undefined)?.identificationByPassportId as boolean | undefined}
          onChange={(v) =>
            onChange({
              ...value,
              railTicket: {
                ...value.railTicket,
                controlDetail: { ...value.railTicket.controlDetail, identificationByPassportId: v },
              },
            })
          }
        />
        <CheckboxField
          label="passportValidationRequired"
          value={(value.railTicket.controlDetail as Record<string, unknown> | undefined)?.passportValidationRequired as boolean | undefined}
          onChange={(v) =>
            onChange({
              ...value,
              railTicket: {
                ...value.railTicket,
                controlDetail: { ...value.railTicket.controlDetail, passportValidationRequired: v },
              },
            })
          }
        />
        <CheckboxField
          label="onlineValidationRequired"
          value={(value.railTicket.controlDetail as Record<string, unknown> | undefined)?.onlineValidationRequired as boolean | undefined}
          onChange={(v) =>
            onChange({
              ...value,
              railTicket: {
                ...value.railTicket,
                controlDetail: { ...value.railTicket.controlDetail, onlineValidationRequired: v },
              },
            })
          }
        />
        <CheckboxField
          label="ageCheckRequired"
          value={(value.railTicket.controlDetail as Record<string, unknown> | undefined)?.ageCheckRequired as boolean | undefined}
          onChange={(v) =>
            onChange({
              ...value,
              railTicket: {
                ...value.railTicket,
                controlDetail: { ...value.railTicket.controlDetail, ageCheckRequired: v },
              },
            })
          }
        />
        <CheckboxField
          label="reductionCardCheckRequired"
          value={(value.railTicket.controlDetail as Record<string, unknown> | undefined)?.reductionCardCheckRequired as boolean | undefined}
          onChange={(v) =>
            onChange({
              ...value,
              railTicket: {
                ...value.railTicket,
                controlDetail: { ...value.railTicket.controlDetail, reductionCardCheckRequired: v },
              },
            })
          }
        />
        <div className="col-span-2">
          <TextField
            label="infoText"
            value={(value.railTicket.controlDetail as Record<string, unknown> | undefined)?.infoText as string | undefined}
            onChange={(v) =>
              onChange({
                ...value,
                railTicket: {
                  ...value.railTicket,
                  controlDetail: { ...value.railTicket.controlDetail, infoText: v },
                },
              })
            }
          />
        </div>
        <JsonField
          label="identificationByCardReference"
          value={(value.railTicket.controlDetail as Record<string, unknown> | undefined)?.identificationByCardReference}
          onChange={(v) =>
            onChange({
              ...value,
              railTicket: {
                ...value.railTicket,
                controlDetail: { ...value.railTicket.controlDetail, identificationByCardReference: v },
              },
            })
          }
        />
        <JsonField
          label="includedTickets"
          value={(value.railTicket.controlDetail as Record<string, unknown> | undefined)?.includedTickets}
          onChange={(v) =>
            onChange({
              ...value,
              railTicket: {
                ...value.railTicket,
                controlDetail: { ...value.railTicket.controlDetail, includedTickets: v },
              },
            })
          }
        />
      </ToggleSection>
    </div>
  );
}
