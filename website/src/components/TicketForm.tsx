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
}

// ---------------------------------------------------------------------------
// Reusable field primitives
// ---------------------------------------------------------------------------

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="space-y-2">
      <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wide">{title}</h4>
      <div className="grid grid-cols-2 gap-x-4 gap-y-2">{children}</div>
    </div>
  );
}

function ToggleSection({
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

function NumberField({
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

function OptionalNumberField({
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
// Main form component
// ---------------------------------------------------------------------------

export default function TicketForm({ value, onChange }: Props) {
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
  const hasDynamic = !!value.dynamicData;

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
      {/* Header */}
      <Section title="Header">
        <SelectField
          label="Header Version"
          value={value.headerVersion}
          options={[
            { label: 'v2', value: 2 },
            { label: 'v1', value: 1 },
          ]}
          onChange={(v) => update({ headerVersion: v })}
        />
        <SelectField
          label="FCB Version"
          value={value.fcbVersion}
          options={[
            { label: 'FCB3', value: 3 },
            { label: 'FCB2', value: 2 },
            { label: 'FCB1', value: 1 },
          ]}
          onChange={(v) => update({ fcbVersion: v })}
        />
      </Section>

      {/* Security */}
      <Section title="Security">
        <NumberField
          label="Provider (RICS)"
          value={value.securityProviderNum}
          onChange={(v) => update({ securityProviderNum: v })}
          placeholder="e.g. 1187"
        />
        <NumberField
          label="Key ID"
          value={value.keyId}
          onChange={(v) => update({ keyId: v })}
          placeholder="e.g. 1"
        />
        <OptionalNumberField
          label="End of Validity Year"
          value={value.endOfValidityYear}
          onChange={(v) => update({ endOfValidityYear: v })}
          placeholder="2016-2269"
          defaultValue={now.getFullYear()}
        />
        <OptionalNumberField
          label="End of Validity Day"
          value={value.endOfValidityDay}
          onChange={(v) => update({ endOfValidityDay: v })}
          placeholder="1-366"
          defaultValue={dayOfYear}
        />
        <OptionalNumberField
          label="End of Validity Time"
          value={value.endOfValidityTime}
          onChange={(v) => update({ endOfValidityTime: v })}
          placeholder="0-1439 (minutes)"
        />
        <OptionalNumberField
          label="Validity Duration"
          value={value.validityDuration}
          onChange={(v) => update({ validityDuration: v })}
          placeholder="1-3600 (minutes)"
        />
      </Section>

      {/* Issuing Detail */}
      <Section title="Issuing Detail">
        <OptionalNumberField
          label="Security Provider (RICS)"
          value={value.railTicket.issuingDetail.securityProviderNum}
          onChange={(v) => updateIssuing({ securityProviderNum: v })}
          placeholder="e.g. 1187"
        />
        <OptionalNumberField
          label="Issuer (RICS)"
          value={value.railTicket.issuingDetail.issuerNum}
          onChange={(v) => updateIssuing({ issuerNum: v })}
          placeholder="e.g. 1187"
        />
        <NumberField
          label="Issuing Year"
          value={value.railTicket.issuingDetail.issuingYear}
          onChange={(v) => updateIssuing({ issuingYear: v ?? now.getFullYear() })}
          placeholder={String(now.getFullYear())}
        />
        <NumberField
          label="Issuing Day"
          value={value.railTicket.issuingDetail.issuingDay}
          onChange={(v) => updateIssuing({ issuingDay: v ?? dayOfYear })}
          placeholder={String(dayOfYear)}
        />
        <OptionalNumberField
          label="Issuing Time"
          value={value.railTicket.issuingDetail.issuingTime}
          onChange={(v) => updateIssuing({ issuingTime: v })}
          placeholder="Minutes since midnight"
        />
        <OptionalTextField
          label="Issuer Name"
          value={value.railTicket.issuingDetail.issuerName}
          onChange={(v) => updateIssuing({ issuerName: v })}
          placeholder="e.g. SNCF"
        />
        <OptionalTextField
          label="Currency"
          value={value.railTicket.issuingDetail.currency}
          onChange={(v) => updateIssuing({ currency: v })}
          placeholder="EUR"
        />
        <OptionalNumberField
          label="Currency Fract"
          value={value.railTicket.issuingDetail.currencyFract}
          onChange={(v) => updateIssuing({ currencyFract: v })}
          placeholder="e.g. 2"
        />
        <OptionalTextField
          label="PNR"
          value={value.railTicket.issuingDetail.issuerPNR}
          onChange={(v) => updateIssuing({ issuerPNR: v })}
        />
        <div className="col-span-2 flex gap-4">
          <CheckboxField
            label="Specimen"
            value={value.railTicket.issuingDetail.specimen}
            onChange={(v) => updateIssuing({ specimen: v })}
          />
          <CheckboxField
            label="Secure Paper"
            value={value.railTicket.issuingDetail.securePaperTicket}
            onChange={(v) => updateIssuing({ securePaperTicket: v })}
          />
          <CheckboxField
            label="Activated"
            value={value.railTicket.issuingDetail.activated}
            onChange={(v) => updateIssuing({ activated: v })}
          />
        </div>
      </Section>

      {/* Intercode 6 Issuing */}
      <ToggleSection
        title="Intercode 6 Issuing"
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
        <NumberField
          label="Intercode Version"
          value={value.railTicket.issuingDetail.intercodeIssuing?.intercodeVersion}
          onChange={(v) => updateIntercodeIssuing({ intercodeVersion: v ?? 1 })}
        />
        <NumberField
          label="Intercode Instanciation"
          value={value.railTicket.issuingDetail.intercodeIssuing?.intercodeInstanciation}
          onChange={(v) => updateIntercodeIssuing({ intercodeInstanciation: v ?? 1 })}
        />
        <BytesHexField
          label="Network ID (hex)"
          value={value.railTicket.issuingDetail.intercodeIssuing?.networkId}
          onChange={(v) => updateIntercodeIssuing({ networkId: v })}
          placeholder="e.g. 0087"
        />
        <div /> {/* spacer */}

        {/* Product Retailer sub-section */}
        <div className="col-span-2 mt-1 pt-1 border-t border-gray-100">
          <span className="text-xs text-gray-400">Product Retailer</span>
        </div>
        <StringSelectField
          label="Retail Channel"
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
          label="Generator ID"
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
          label="Server ID"
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
          label="Retailer ID"
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
          label="Retail Point ID"
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

      {/* Traveler Detail */}
      <ToggleSection
        title="Traveler Detail"
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
          label="Preferred Language"
          value={value.railTicket.travelerDetail?.preferredLanguage}
          onChange={(v) => updateTraveler({ preferredLanguage: v })}
          placeholder="e.g. EN"
        />
        <OptionalTextField
          label="Group Name"
          value={value.railTicket.travelerDetail?.groupName}
          onChange={(v) => updateTraveler({ groupName: v })}
        />

        <div className="col-span-2 mt-1 pt-1 border-t border-gray-100">
          <span className="text-xs text-gray-400">Traveler</span>
        </div>

        <OptionalTextField
          label="First Name"
          value={traveler?.firstName}
          onChange={(v) => updateTravelerPerson({ firstName: v })}
        />
        <OptionalTextField
          label="Second Name"
          value={traveler?.secondName}
          onChange={(v) => updateTravelerPerson({ secondName: v })}
        />
        <OptionalTextField
          label="Last Name"
          value={traveler?.lastName}
          onChange={(v) => updateTravelerPerson({ lastName: v })}
        />
        <OptionalTextField
          label="Title"
          value={traveler?.title}
          onChange={(v) => updateTravelerPerson({ title: v })}
        />
        <StringSelectField
          label="Gender"
          value={traveler?.gender}
          options={[
            { label: 'Male', value: 'male' },
            { label: 'Female', value: 'female' },
            { label: 'Other', value: 'other' },
          ]}
          onChange={(v) => updateTravelerPerson({ gender: v })}
          allowEmpty
        />
        <OptionalTextField
          label="ID Card"
          value={traveler?.idCard}
          onChange={(v) => updateTravelerPerson({ idCard: v })}
        />
        <OptionalTextField
          label="Passport ID"
          value={traveler?.passportId}
          onChange={(v) => updateTravelerPerson({ passportId: v })}
        />
        <OptionalTextField
          label="Customer ID (IA5)"
          value={traveler?.customerIdIA5}
          onChange={(v) => updateTravelerPerson({ customerIdIA5: v })}
        />
        <OptionalNumberField
          label="Customer ID (num)"
          value={traveler?.customerIdNum}
          onChange={(v) => updateTravelerPerson({ customerIdNum: v })}
        />
        <OptionalNumberField
          label="Year of Birth"
          value={traveler?.yearOfBirth}
          onChange={(v) => updateTravelerPerson({ yearOfBirth: v })}
          placeholder="e.g. 1990"
        />
        <OptionalNumberField
          label="Month of Birth"
          value={traveler?.monthOfBirth}
          onChange={(v) => updateTravelerPerson({ monthOfBirth: v })}
          placeholder="1-12"
        />
        <OptionalNumberField
          label="Day of Birth (v1)"
          value={traveler?.dayOfBirth}
          onChange={(v) => updateTravelerPerson({ dayOfBirth: v })}
          placeholder="0-370 (day of year)"
        />
        <OptionalNumberField
          label="Day of Birth in Month (v2/v3)"
          value={traveler?.dayOfBirthInMonth}
          onChange={(v) => updateTravelerPerson({ dayOfBirthInMonth: v })}
          placeholder="1-31"
        />
        <CheckboxField
          label="Ticket Holder"
          value={traveler?.ticketHolder}
          onChange={(v) => updateTravelerPerson({ ticketHolder: v })}
        />
        <OptionalTextField
          label="Passenger Type"
          value={traveler?.passengerType as string | undefined}
          onChange={(v) => updateTravelerPerson({ passengerType: v })}
        />
        <CheckboxField
          label="Reduced Mobility"
          value={traveler?.passengerWithReducedMobility}
          onChange={(v) => updateTravelerPerson({ passengerWithReducedMobility: v })}
        />
        <OptionalNumberField
          label="Country of Residence"
          value={traveler?.countryOfResidence}
          onChange={(v) => updateTravelerPerson({ countryOfResidence: v })}
        />
        <OptionalNumberField
          label="Country of Passport"
          value={traveler?.countryOfPassport}
          onChange={(v) => updateTravelerPerson({ countryOfPassport: v })}
        />
        <OptionalNumberField
          label="Country of ID Card"
          value={traveler?.countryOfIdCard}
          onChange={(v) => updateTravelerPerson({ countryOfIdCard: v })}
        />
      </ToggleSection>

      {/* Transport Documents */}
      <Section title="Transport Documents">
        <JsonField
          label="Documents (JSON array)"
          value={value.railTicket.transportDocument}
          onChange={(v) =>
            onChange({
              ...value,
              railTicket: { ...value.railTicket, transportDocument: v as TransportDocumentInput[] | undefined },
            })
          }
        />
      </Section>

      {/* Control Detail */}
      <ToggleSection
        title="Control Detail"
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
          label="ID by ID Card"
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
          label="ID by Passport"
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
          label="Passport Validation Required"
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
          label="Online Validation Required"
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
          label="Age Check Required"
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
          label="Reduction Card Check Required"
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
            label="Info Text"
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
          label="Card References (JSON)"
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
          label="Included Tickets (JSON)"
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

      {/* Intercode 6 Dynamic Data */}
      <ToggleSection
        title="Intercode 6 Dynamic Data"
        enabled={hasDynamic}
        onToggle={(v) => {
          update({
            dynamicData: v
              ? { rics: value.securityProviderNum ?? 0, dynamicContentDay: 0 }
              : undefined,
          });
        }}
      >
        <NumberField
          label="RICS"
          value={value.dynamicData?.rics}
          onChange={(v) =>
            update({
              dynamicData: { ...value.dynamicData!, rics: v ?? 0 },
            })
          }
          placeholder="e.g. 3703"
        />
        <NumberField
          label="Day"
          value={value.dynamicData?.dynamicContentDay}
          onChange={(v) =>
            update({
              dynamicData: { ...value.dynamicData!, dynamicContentDay: v },
            })
          }
        />
        <OptionalNumberField
          label="Time"
          value={value.dynamicData?.dynamicContentTime}
          onChange={(v) =>
            update({
              dynamicData: { ...value.dynamicData!, dynamicContentTime: v },
            })
          }
        />
        <OptionalNumberField
          label="UTC Offset"
          value={value.dynamicData?.dynamicContentUTCOffset}
          onChange={(v) =>
            update({
              dynamicData: { ...value.dynamicData!, dynamicContentUTCOffset: v },
            })
          }
        />
        <OptionalNumberField
          label="Duration"
          value={value.dynamicData?.dynamicContentDuration}
          onChange={(v) =>
            update({
              dynamicData: { ...value.dynamicData!, dynamicContentDuration: v },
            })
          }
        />
      </ToggleSection>
    </div>
  );
}
