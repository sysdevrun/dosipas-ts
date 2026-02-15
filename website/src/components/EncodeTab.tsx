import { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import type { UicBarcodeTicketInput, UicDynamicContentDataInput, CurveName } from 'dosipas-ts';
import TicketForm, { ToggleSection, NumberField, OptionalNumberField } from './TicketForm';
import KeyPairInput from './KeyPairInput';
import AztecBarcode from './AztecBarcode';
import {
  signLevel1Data,
  signLevel2Data,
  encodeTicket,
  signTicket,
  bytesToHex,
  hexToBytes,
  getPublicKey,
  CURVES,
  type KeyPair,
} from '../lib/signing';

/** NIST FIPS 186-4 ECDSA P-256 KeyPair test vector private keys (from CAVP KeyPair.rsp). */
const FIPS_TEST_KEY_1 = 'c9806898a0334916c860748880a541f093b579a9b1f32934d86c363c39800357';
const FIPS_TEST_KEY_2 = '710735c8388f48c684a97bd66751cc5f5a122d6b9a96a2dbe73662f78217446d';

interface Props {
  onDecode: (hex: string) => void;
  prefillInput: UicBarcodeTicketInput | null;
  onPrefillConsumed: () => void;
}

function getDefaultInput(): UicBarcodeTicketInput {
  const now = new Date();
  const dayOfYear = Math.floor(
    (now.getTime() - new Date(now.getFullYear(), 0, 0).getTime()) / 86400000,
  );
  return {
    headerVersion: 2,
    fcbVersion: 3,
    securityProviderNum: 9999,
    keyId: 1,
    railTicket: {
      issuingDetail: {
        issuerNum: 9999,
        issuingYear: now.getFullYear(),
        issuingDay: dayOfYear,
        specimen: true,
        activated: true,
      },
      transportDocument: [
        {
          ticketType: 'openTicket',
          ticket: {
            returnIncluded: false,
          },
        },
      ],
    },
  };
}

/** JSON replacer that serializes Uint8Array as hex strings for display. */
function jsonReplacer(_key: string, value: unknown): unknown {
  if (value instanceof Uint8Array) {
    return `<hex:${Array.from(value).map((b) => b.toString(16).padStart(2, '0')).join('')}>`;
  }
  return value;
}

// ---------------------------------------------------------------------------
// Signature section component
// ---------------------------------------------------------------------------

function SignatureSection({
  label,
  sigHex,
  onSigHexChange,
  stale,
  canGenerate,
  onGenerate,
  sigError,
}: {
  label: string;
  sigHex: string;
  onSigHexChange: (hex: string) => void;
  stale: boolean;
  canGenerate: boolean;
  onGenerate: () => void;
  sigError: string | null;
}) {
  return (
    <div className="space-y-2 border-t border-gray-100 pt-3 mt-3">
      <div className="flex items-center justify-between">
        <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wide">
          {label}
        </h4>
        {canGenerate && (
          <button
            onClick={onGenerate}
            className="text-xs px-3 py-1 bg-green-100 text-green-700 rounded hover:bg-green-200 transition-colors"
          >
            {sigHex ? 'Regenerate' : 'Generate'}
          </button>
        )}
      </div>
      {stale && sigHex && (
        <div className="flex items-center gap-1.5 px-2.5 py-1.5 bg-amber-50 border border-amber-200 rounded text-xs text-amber-700">
          <span>Data has changed since this signature was generated. The signature is likely outdated.</span>
        </div>
      )}
      <textarea
        value={sigHex}
        onChange={(e) => onSigHexChange(e.target.value.replace(/[^0-9a-fA-F]/g, ''))}
        placeholder="Signature hex (generate or paste)..."
        className="w-full px-3 py-1.5 font-mono text-xs bg-white border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent h-16 resize-y"
        spellCheck={false}
      />
      {sigError && (
        <p className="text-xs text-red-600">{sigError}</p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main EncodeTab component
// ---------------------------------------------------------------------------

export default function EncodeTab({ onDecode, prefillInput, onPrefillConsumed }: Props) {
  const [input, setInput] = useState<UicBarcodeTicketInput>(getDefaultInput);

  // Level 1 key state
  const [l1Curve, setL1Curve] = useState('P-256');
  const [l1PrivKey, setL1PrivKey] = useState('');
  const [l1PubKey, setL1PubKey] = useState('');

  // Level 1 signature state
  const [l1SigHex, setL1SigHex] = useState('');
  const [l1SigStale, setL1SigStale] = useState(false);
  const [l1SigError, setL1SigError] = useState<string | null>(null);

  // Level 2 key state
  const [l2Enabled, setL2Enabled] = useState(false);
  const [l2Curve, setL2Curve] = useState('P-256');
  const [l2PrivKey, setL2PrivKey] = useState('');
  const [l2PubKey, setL2PubKey] = useState('');

  // Level 2 signature state
  const [l2SigHex, setL2SigHex] = useState('');
  const [l2SigStale, setL2SigStale] = useState(false);
  const [l2SigError, setL2SigError] = useState<string | null>(null);

  // UI state
  const [jsonOpen, setJsonOpen] = useState(false);
  const [dynamicRefreshEnabled, setDynamicRefreshEnabled] = useState(false);
  const [dynamicRefreshInterval, setDynamicRefreshInterval] = useState(10);
  const [countdown, setCountdown] = useState<number | null>(null);

  // Encoding output state
  const [hex, setHex] = useState('');
  const [bytes, setBytes] = useState<Uint8Array>(new Uint8Array());
  const [encodeError, setEncodeError] = useState<string | null>(null);

  // Keep mutable refs for the regeneration interval
  const regenRef = useRef<{
    input: UicBarcodeTicketInput;
    l1PrivKey: string;
    l1Curve: string;
    l2PrivKey: string;
    l2Curve: string;
  } | null>(null);

  // -------------------------------------------------------------------------
  // Input change handler - marks signatures as stale
  // -------------------------------------------------------------------------

  const handleInputChange = useCallback((newInput: UicBarcodeTicketInput) => {
    setInput(newInput);
    // Mark signatures stale when data changes
    if (l1SigHex) setL1SigStale(true);
    if (l2SigHex) setL2SigStale(true);
  }, [l1SigHex, l2SigHex]);

  // Also mark sigs stale when key/curve changes (affects OIDs in signed data)
  useEffect(() => {
    if (l1SigHex) setL1SigStale(true);
    if (l2SigHex) setL2SigStale(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [l1Curve, l2Curve, l2Enabled]);

  // -------------------------------------------------------------------------
  // Apply prefill from decoded ticket
  // -------------------------------------------------------------------------

  useEffect(() => {
    if (prefillInput) {
      setInput(prefillInput);
      // Enable L2 if prefill has dynamic data
      if (prefillInput.dynamicData || prefillInput.dynamicContentData) {
        setL2Enabled(true);
      }
      // Populate signatures from prefilled input if present
      if (prefillInput.level1Signature && prefillInput.level1Signature.length > 0) {
        setL1SigHex(bytesToHex(prefillInput.level1Signature));
      } else {
        setL1SigHex('');
      }
      setL1SigStale(false);
      if (prefillInput.level2Signature && prefillInput.level2Signature.length > 0) {
        setL2SigHex(bytesToHex(prefillInput.level2Signature));
      } else {
        setL2SigHex('');
      }
      setL2SigStale(false);
      onPrefillConsumed();
    }
  }, [prefillInput, onPrefillConsumed]);

  // -------------------------------------------------------------------------
  // Build a prepared input with OIDs and L2 public key set
  // -------------------------------------------------------------------------

  const buildPreparedInput = useCallback((): UicBarcodeTicketInput => {
    const l1CurveConfig = CURVES[l1Curve as CurveName];
    const prepared: UicBarcodeTicketInput = {
      ...input,
      level1KeyAlg: l1CurveConfig.keyAlgOid,
      level1SigningAlg: l1CurveConfig.sigAlgOid,
    };

    if (l2Enabled && l2PubKey) {
      const l2CurveConfig = CURVES[l2Curve as CurveName];
      prepared.level2KeyAlg = l2CurveConfig.keyAlgOid;
      prepared.level2SigningAlg = l2CurveConfig.sigAlgOid;
      prepared.level2PublicKey = hexToBytes(l2PubKey);
    }

    return prepared;
  }, [input, l1Curve, l2Enabled, l2Curve, l2PubKey]);

  // -------------------------------------------------------------------------
  // Generate Level 1 signature
  // -------------------------------------------------------------------------

  const handleGenerateL1Sig = useCallback(() => {
    try {
      const prepared = buildPreparedInput();
      const sig = signLevel1Data(prepared, l1PrivKey, l1Curve);
      const sigHex = bytesToHex(sig);
      setL1SigHex(sigHex);
      setL1SigStale(false);
      setL1SigError(null);
      // L2 depends on L1 signature, so mark L2 stale
      if (l2SigHex) setL2SigStale(true);
    } catch (e) {
      setL1SigError(e instanceof Error ? e.message : 'Failed to generate L1 signature');
    }
  }, [buildPreparedInput, l1PrivKey, l1Curve, l2SigHex]);

  // -------------------------------------------------------------------------
  // Generate Level 2 signature
  // -------------------------------------------------------------------------

  const handleGenerateL2Sig = useCallback(() => {
    if (!l1SigHex) {
      setL2SigError('Level 1 signature must be generated first');
      return;
    }
    try {
      const prepared = buildPreparedInput();
      prepared.level1Signature = hexToBytes(l1SigHex);
      const sig = signLevel2Data(prepared, l2PrivKey, l2Curve);
      const sigHex = bytesToHex(sig);
      setL2SigHex(sigHex);
      setL2SigStale(false);
      setL2SigError(null);
    } catch (e) {
      setL2SigError(e instanceof Error ? e.message : 'Failed to generate L2 signature');
    }
  }, [buildPreparedInput, l1SigHex, l2PrivKey, l2Curve]);

  // -------------------------------------------------------------------------
  // Encode ticket with existing signatures
  // -------------------------------------------------------------------------

  const handleEncode = useCallback(() => {
    try {
      const prepared = buildPreparedInput();
      prepared.level1Signature = l1SigHex ? hexToBytes(l1SigHex) : new Uint8Array(0);
      prepared.level2Signature = l2SigHex ? hexToBytes(l2SigHex) : new Uint8Array(0);

      const encodedBytes = encodeTicket(prepared);
      const encodedHex = bytesToHex(encodedBytes);
      setHex(encodedHex);
      setBytes(encodedBytes);
      setEncodeError(null);

      // Start dynamic refresh countdown if enabled
      if (l2Enabled && dynamicRefreshEnabled && (input.dynamicData || input.dynamicContentData) && l1PrivKey && l2PrivKey) {
        regenRef.current = { input, l1PrivKey, l1Curve, l2PrivKey, l2Curve };
        setCountdown(dynamicRefreshInterval);
      } else {
        regenRef.current = null;
        setCountdown(null);
      }
    } catch (e) {
      setHex('');
      setBytes(new Uint8Array());
      setEncodeError(e instanceof Error ? e.message : 'Encode failed');
    }
  }, [buildPreparedInput, l1SigHex, l2SigHex, l2Enabled, dynamicRefreshEnabled, input, l1PrivKey, l1Curve, l2PrivKey, l2Curve, dynamicRefreshInterval]);

  // -------------------------------------------------------------------------
  // Dynamic content refresh (re-signs and re-encodes periodically)
  // -------------------------------------------------------------------------

  useEffect(() => {
    if (countdown === null) return;

    const timer = setInterval(() => {
      setCountdown((prev) => {
        if (prev === null) return null;
        if (prev <= 1) {
          const params = regenRef.current;
          if (params) {
            const now = new Date();
            const startOfYear = new Date(now.getFullYear(), 0, 0);
            const dayOfYear =
              Math.floor(
                (now.getTime() - startOfYear.getTime()) / 86400000,
              ) - 1;
            const secondsSinceMidnight =
              now.getHours() * 3600 + now.getMinutes() * 60 + now.getSeconds();

            let updatedInput: UicBarcodeTicketInput;
            if (params.input.dynamicContentData) {
              updatedInput = {
                ...params.input,
                dynamicContentData: {
                  ...params.input.dynamicContentData,
                  dynamicContentTimeStamp: {
                    day: dayOfYear,
                    time: secondsSinceMidnight,
                  },
                },
              };
            } else {
              updatedInput = {
                ...params.input,
                dynamicData: {
                  ...params.input.dynamicData!,
                  dynamicContentDay: dayOfYear,
                  dynamicContentTime: secondsSinceMidnight,
                },
              };
            }
            regenRef.current = { ...params, input: updatedInput };
            setInput(updatedInput);

            // Full sign+encode for dynamic refresh
            try {
              const level1Key: KeyPair = {
                privateKey: hexToBytes(params.l1PrivKey),
                publicKey: getPublicKey(params.l1PrivKey, params.l1Curve),
                curve: params.l1Curve as CurveName,
              };
              const level2Key: KeyPair = {
                privateKey: hexToBytes(params.l2PrivKey),
                publicKey: getPublicKey(params.l2PrivKey, params.l2Curve),
                curve: params.l2Curve as CurveName,
              };
              const refreshedBytes = signTicket(updatedInput, level1Key, level2Key);
              const refreshedHex = bytesToHex(refreshedBytes);
              setHex(refreshedHex);
              setBytes(refreshedBytes);
              // Update signature fields to match
              // Extract the sigs from the signed output by re-signing
              const l1CurveConfig = CURVES[params.l1Curve as CurveName];
              const l2CurveConfig = CURVES[params.l2Curve as CurveName];
              const prepInput: UicBarcodeTicketInput = {
                ...updatedInput,
                level1KeyAlg: l1CurveConfig.keyAlgOid,
                level1SigningAlg: l1CurveConfig.sigAlgOid,
                level2KeyAlg: l2CurveConfig.keyAlgOid,
                level2SigningAlg: l2CurveConfig.sigAlgOid,
                level2PublicKey: level2Key.publicKey,
              };
              const l1Sig = signLevel1Data(prepInput, params.l1PrivKey, params.l1Curve);
              setL1SigHex(bytesToHex(l1Sig));
              setL1SigStale(false);
              prepInput.level1Signature = l1Sig;
              const l2Sig = signLevel2Data(prepInput, params.l2PrivKey, params.l2Curve);
              setL2SigHex(bytesToHex(l2Sig));
              setL2SigStale(false);
              setEncodeError(null);
            } catch (e) {
              setEncodeError(e instanceof Error ? e.message : 'Dynamic refresh failed');
            }
          }
          return dynamicRefreshInterval;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [countdown === null, dynamicRefreshInterval]);

  // Update regeneration params when input or keys change (while regeneration is active)
  useEffect(() => {
    if (regenRef.current) {
      regenRef.current = { input, l1PrivKey, l1Curve, l2PrivKey, l2Curve };
    }
  }, [input, l1PrivKey, l1Curve, l2PrivKey, l2Curve]);

  // Stop regeneration when L2 is disabled or dynamic refresh is turned off
  useEffect(() => {
    if (!l2Enabled || !dynamicRefreshEnabled || (!input.dynamicData && !input.dynamicContentData)) {
      regenRef.current = null;
      setCountdown(null);
    }
  }, [l2Enabled, dynamicRefreshEnabled, input.dynamicData, input.dynamicContentData]);

  // -------------------------------------------------------------------------
  // Dynamic data update helper
  // -------------------------------------------------------------------------

  const updateDynamicData = useCallback((partial: Partial<UicBarcodeTicketInput['dynamicData'] & object>) => {
    handleInputChange({
      ...input,
      dynamicData: { ...input.dynamicData!, ...partial },
    });
  }, [input, handleInputChange]);

  // -------------------------------------------------------------------------
  // Misc helpers
  // -------------------------------------------------------------------------

  const copyHex = () => {
    navigator.clipboard.writeText(hex);
  };

  const jsonPreview = useMemo(() => jsonReplacer
    ? JSON.stringify(input, jsonReplacer, 2)
    : JSON.stringify(input, null, 2),
  [input]);

  const copyJson = () => {
    navigator.clipboard.writeText(jsonPreview);
  };

  const hasDynamic = !!input.dynamicData || !!input.dynamicContentData;
  const dynamicFormat: 'intercode' | 'fdc1' = input.dynamicContentData ? 'fdc1' : 'intercode';
  const l2KeyPresent = l2Enabled && !!l2PrivKey;

  return (
    <div className="space-y-6">
      {/* ================================================================= */}
      {/* LEVEL 1 SECTION                                                   */}
      {/* ================================================================= */}
      <div className="bg-white rounded-lg border border-gray-200 p-4 space-y-4">
        <h3 className="text-sm font-semibold text-gray-700 uppercase tracking-wide">
          Level 1
        </h3>

        {/* Level 1 Key */}
        <KeyPairInput
          label="Level 1 Key"
          curve={l1Curve}
          onCurveChange={setL1Curve}
          privateKeyHex={l1PrivKey}
          onPrivateKeyChange={setL1PrivKey}
          publicKeyHex={l1PubKey}
          onPublicKeyChange={setL1PubKey}
          fipsTestKey={FIPS_TEST_KEY_1}
        />

        {/* Level 1 Data */}
        <TicketForm
          value={input}
          onChange={handleInputChange}
        />

        {/* Level 1 Signature */}
        <SignatureSection
          label="Level 1 Signature"
          sigHex={l1SigHex}
          onSigHexChange={(hex) => {
            setL1SigHex(hex);
            setL1SigStale(false);
            // L2 depends on L1 sig
            if (l2SigHex) setL2SigStale(true);
          }}
          stale={l1SigStale}
          canGenerate={!!l1PrivKey}
          onGenerate={handleGenerateL1Sig}
          sigError={l1SigError}
        />
      </div>

      {/* ================================================================= */}
      {/* LEVEL 2 SECTION                                                   */}
      {/* ================================================================= */}
      <div className="bg-white rounded-lg border border-gray-200 p-4 space-y-4">
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={l2Enabled}
            onChange={(e) => setL2Enabled(e.target.checked)}
            className="rounded border-gray-300"
          />
          <h3 className="text-sm font-semibold text-gray-700 uppercase tracking-wide">
            Level 2 (dynamic barcode)
          </h3>
        </label>

        {l2Enabled && (
          <>
            {/* Level 2 Key */}
            <KeyPairInput
              label="Level 2 Key"
              curve={l2Curve}
              onCurveChange={setL2Curve}
              privateKeyHex={l2PrivKey}
              onPrivateKeyChange={setL2PrivKey}
              publicKeyHex={l2PubKey}
              onPublicKeyChange={setL2PubKey}
              fipsTestKey={FIPS_TEST_KEY_2}
            />

            {/* level2Data */}
            <ToggleSection
              title="level2Data"
              enabled={hasDynamic}
              onToggle={(v) => {
                if (v) {
                  handleInputChange({
                    ...input,
                    dynamicContentData: {},
                    dynamicData: undefined,
                  });
                } else {
                  handleInputChange({
                    ...input,
                    dynamicData: undefined,
                    dynamicContentData: undefined,
                  });
                }
              }}
            >
              {/* Format selector */}
              <div className="col-span-2 flex items-center gap-3 mb-1">
                <span className="text-xs text-gray-500">Format</span>
                <label className="flex items-center gap-1">
                  <input
                    type="radio"
                    name="dynamicFormat"
                    checked={dynamicFormat === 'fdc1'}
                    onChange={() => {
                      handleInputChange({
                        ...input,
                        dynamicContentData: {},
                        dynamicData: undefined,
                      });
                    }}
                    className="text-blue-600"
                  />
                  <span className="text-xs text-gray-700">FDC1</span>
                </label>
                <label className="flex items-center gap-1">
                  <input
                    type="radio"
                    name="dynamicFormat"
                    checked={dynamicFormat === 'intercode'}
                    onChange={() => {
                      handleInputChange({
                        ...input,
                        dynamicData: { rics: input.securityProviderNum ?? 0, dynamicContentDay: 0 },
                        dynamicContentData: undefined,
                      });
                    }}
                    className="text-blue-600"
                  />
                  <span className="text-xs text-gray-700">Intercode 6 (_RICS.ID1)</span>
                </label>
              </div>

              {dynamicFormat === 'fdc1' && (
                <>
                  <NumberField
                    label="dynamicContentTimeStamp.day"
                    value={input.dynamicContentData?.dynamicContentTimeStamp?.day}
                    onChange={(v) => {
                      const ts = input.dynamicContentData?.dynamicContentTimeStamp;
                      handleInputChange({
                        ...input,
                        dynamicContentData: {
                          ...input.dynamicContentData,
                          dynamicContentTimeStamp: v != null ? { day: v, time: ts?.time ?? 0 } : undefined,
                        },
                      });
                    }}
                    placeholder="Day of year (1-366)"
                  />
                  <NumberField
                    label="dynamicContentTimeStamp.time"
                    value={input.dynamicContentData?.dynamicContentTimeStamp?.time}
                    onChange={(v) => {
                      const ts = input.dynamicContentData?.dynamicContentTimeStamp;
                      handleInputChange({
                        ...input,
                        dynamicContentData: {
                          ...input.dynamicContentData,
                          dynamicContentTimeStamp: v != null ? { day: ts?.day ?? 1, time: v } : undefined,
                        },
                      });
                    }}
                    placeholder="Seconds since midnight (0-86399)"
                  />
                </>
              )}

              {dynamicFormat === 'intercode' && (
                <>
                  <NumberField
                    label="rics"
                    value={input.dynamicData?.rics}
                    onChange={(v) => updateDynamicData({ rics: v ?? 0 })}
                    placeholder="e.g. 3703"
                  />
                  <NumberField
                    label="dynamicContentDay"
                    value={input.dynamicData?.dynamicContentDay}
                    onChange={(v) => updateDynamicData({ dynamicContentDay: v })}
                  />
                  <OptionalNumberField
                    label="dynamicContentTime"
                    value={input.dynamicData?.dynamicContentTime}
                    onChange={(v) => updateDynamicData({ dynamicContentTime: v })}
                  />
                  <OptionalNumberField
                    label="dynamicContentUTCOffset"
                    value={input.dynamicData?.dynamicContentUTCOffset}
                    onChange={(v) => updateDynamicData({ dynamicContentUTCOffset: v })}
                  />
                  <OptionalNumberField
                    label="dynamicContentDuration"
                    value={input.dynamicData?.dynamicContentDuration}
                    onChange={(v) => updateDynamicData({ dynamicContentDuration: v })}
                  />
                </>
              )}

              {l2KeyPresent && (
                <div className="col-span-2 space-y-2 border-t border-gray-100 pt-2 mt-1">
                  <label className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={dynamicRefreshEnabled}
                      onChange={(e) => setDynamicRefreshEnabled(e.target.checked)}
                      className="rounded border-gray-300"
                    />
                    <span className="text-xs text-gray-600">
                      Refresh timestamp automatically
                    </span>
                  </label>
                  {dynamicRefreshEnabled && (
                    <div className="flex items-center gap-2">
                      <label className="text-xs text-gray-500">Interval</label>
                      <input
                        type="number"
                        min={1}
                        value={dynamicRefreshInterval}
                        onChange={(e) =>
                          setDynamicRefreshInterval(Math.max(1, Number(e.target.value)))
                        }
                        className="w-20 px-2 py-1 text-xs border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-400"
                      />
                      <span className="text-xs text-gray-500">seconds</span>
                    </div>
                  )}
                </div>
              )}
            </ToggleSection>

            {/* Level 2 Signature */}
            <SignatureSection
              label="Level 2 Signature"
              sigHex={l2SigHex}
              onSigHexChange={(hex) => {
                setL2SigHex(hex);
                setL2SigStale(false);
              }}
              stale={l2SigStale}
              canGenerate={!!l2PrivKey && !!l1SigHex}
              onGenerate={handleGenerateL2Sig}
              sigError={l2SigError}
            />
          </>
        )}
      </div>

      {/* ================================================================= */}
      {/* ENCODE BUTTON                                                     */}
      {/* ================================================================= */}
      <div className="flex gap-3">
        <button
          onClick={handleEncode}
          disabled={!l1SigHex && !l1PrivKey}
          className="px-6 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors"
        >
          Encode
        </button>
      </div>

      {/* Error display */}
      {encodeError && (
        <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700">
          {encodeError}
        </div>
      )}

      {/* JSON Input Preview */}
      <div className="bg-white rounded-lg border border-gray-200">
        <button
          onClick={() => setJsonOpen(!jsonOpen)}
          className="w-full flex items-center justify-between p-3 text-xs font-semibold text-gray-500 uppercase tracking-wide hover:bg-gray-50 transition-colors"
        >
          <span>JSON Input Preview</span>
          <div className="flex items-center gap-2">
            <button
              onClick={(e) => {
                e.stopPropagation();
                copyJson();
              }}
              className="text-xs text-gray-400 hover:text-gray-600 px-2 py-0.5 rounded hover:bg-gray-100 normal-case font-normal"
            >
              Copy
            </button>
            <span className="text-gray-400">{jsonOpen ? '\u25B2' : '\u25BC'}</span>
          </div>
        </button>
        {jsonOpen && (
          <div className="border-t border-gray-100 p-3">
            <pre className="font-mono text-xs text-gray-700 bg-gray-50 rounded p-3 max-h-64 overflow-auto whitespace-pre-wrap">
              {jsonPreview}
            </pre>
          </div>
        )}
      </div>

      {/* Output */}
      {hex && (
        <div className="space-y-4">
          <div className="bg-white rounded-lg border border-gray-200 p-4 space-y-2">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide">
                Encoded Ticket
              </h3>
              <div className="flex gap-2">
                <button
                  onClick={copyHex}
                  className="text-xs text-gray-500 hover:text-gray-700 px-2 py-1 rounded hover:bg-gray-100"
                >
                  Copy hex
                </button>
                <button
                  onClick={() => onDecode(hex)}
                  className="text-xs text-blue-600 hover:text-blue-800 px-2 py-1 rounded hover:bg-blue-50"
                >
                  Decode this ticket
                </button>
              </div>
            </div>
            <div className="font-mono text-xs break-all text-gray-700 bg-gray-50 rounded p-3 max-h-32 overflow-y-auto">
              {hex}
            </div>
          </div>

          {bytes.length > 0 && (
            <div className="bg-white rounded-lg border border-gray-200 p-4 text-center">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide">
                  Aztec Barcode
                </h3>
                {countdown !== null && (
                  <span className="text-xs text-amber-600 font-medium tabular-nums">
                    Regenerating in {countdown}s
                  </span>
                )}
              </div>
              <AztecBarcode data={bytes} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
