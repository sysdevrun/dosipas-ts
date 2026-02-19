import { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import type { UicBarcodeTicket, UicDynamicContentData, IntercodeDynamicData, CurveName } from 'dosipas-ts';
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

// ---------------------------------------------------------------------------
// Time computation helpers for encode input display
// ---------------------------------------------------------------------------

function formatISOWithTZ(date: Date, utcOffsetQuarterHours?: number): string {
  if (utcOffsetQuarterHours == null) {
    return date.toISOString().replace('.000Z', 'Z');
  }
  const stdOffsetMin = -utcOffsetQuarterHours * 15;
  const localMs = date.getTime() + stdOffsetMin * 60_000;
  const local = new Date(localMs);
  const sign = stdOffsetMin >= 0 ? '+' : '-';
  const absMin = Math.abs(stdOffsetMin);
  const hh = String(Math.floor(absMin / 60)).padStart(2, '0');
  const mm = String(absMin % 60).padStart(2, '0');
  const y = local.getUTCFullYear();
  const mo = String(local.getUTCMonth() + 1).padStart(2, '0');
  const d = String(local.getUTCDate()).padStart(2, '0');
  const h = String(local.getUTCHours()).padStart(2, '0');
  const m = String(local.getUTCMinutes()).padStart(2, '0');
  const s = String(local.getUTCSeconds()).padStart(2, '0');
  return `${y}-${mo}-${d}T${h}:${m}:${s}${sign}${hh}:${mm}`;
}

/** Access helpers for nested ticket structure. */
function getL1(ticket: UicBarcodeTicket) {
  return ticket.level2SignedData.level1Data;
}
function getIss(ticket: UicBarcodeTicket) {
  return getL1(ticket).dataSequence[0]?.decoded?.issuingDetail;
}

function computeIssuingTime(ticket: UicBarcodeTicket): Date | undefined {
  const iss = getIss(ticket);
  if (!iss || iss.issuingYear == null || iss.issuingDay == null) return undefined;
  return new Date(Date.UTC(iss.issuingYear, 0, iss.issuingDay, 0, iss.issuingTime ?? 0));
}

function computeEndOfValidity(ticket: UicBarcodeTicket): Date | undefined {
  const l1 = getL1(ticket);
  if (l1.endOfValidityYear != null && l1.endOfValidityDay != null) {
    return new Date(
      Date.UTC(l1.endOfValidityYear, 0, l1.endOfValidityDay, 0, l1.endOfValidityTime ?? 0)
      + (l1.validityDuration ?? 0) * 1000,
    );
  }
  if (l1.validityDuration != null) {
    const issuing = computeIssuingTime(ticket);
    if (issuing) return new Date(issuing.getTime() + l1.validityDuration * 1000);
  }
  return undefined;
}

function computeFdc1Time(ticket: UicBarcodeTicket): Date | undefined {
  const l2d = ticket.level2SignedData.level2Data;
  if (!l2d || l2d.dataFormat !== 'FDC1') return undefined;
  const ts = (l2d.decoded as UicDynamicContentData | undefined)?.dynamicContentTimeStamp;
  if (!ts) return undefined;
  const iss = getIss(ticket);
  if (!iss) return undefined;
  return new Date(Date.UTC(iss.issuingYear, 0, ts.day, 0, 0, ts.time));
}

function computeIntercodeTime(ticket: UicBarcodeTicket): Date | undefined {
  const l2d = ticket.level2SignedData.level2Data;
  if (!l2d || l2d.dataFormat === 'FDC1') return undefined;
  const dd = l2d.decoded as IntercodeDynamicData | undefined;
  if (!dd) return undefined;
  const iss = getIss(ticket);
  if (!iss) return undefined;
  const issuingDate = new Date(Date.UTC(iss.issuingYear, 0, iss.issuingDay));
  return new Date(
    issuingDate.getTime()
    + (dd.dynamicContentDay ?? 0) * 86400_000
    + (dd.dynamicContentTime ?? 0) * 1000
    + (dd.dynamicContentUTCOffset ?? 0) * 15 * 60_000,
  );
}

function ComputedTimeDisplay({ date, utcOffsetQuarterHours }: { date: Date | undefined; utcOffsetQuarterHours?: number }) {
  if (!date) return null;
  return (
    <span className="text-xs font-mono text-indigo-600 ml-1">
      {formatISOWithTZ(date, utcOffsetQuarterHours)}
    </span>
  );
}

/** Compute UTC day-of-year (1-366) from a Date. */
function utcDayOfYear(date: Date): number {
  const startOfYear = Date.UTC(date.getUTCFullYear(), 0, 0);
  return Math.floor((date.getTime() - startOfYear) / 86400_000);
}

/** NIST FIPS 186-4 ECDSA P-256 KeyPair test vector private keys (from CAVP KeyPair.rsp). */
const FIPS_TEST_KEY_1 = 'c9806898a0334916c860748880a541f093b579a9b1f32934d86c363c39800357';
const FIPS_TEST_KEY_2 = '710735c8388f48c684a97bd66751cc5f5a122d6b9a96a2dbe73662f78217446d';

// ---------------------------------------------------------------------------
// OID select options and component
// ---------------------------------------------------------------------------

const KEY_ALG_OPTIONS = [
  { oid: '1.2.840.10045.3.1.7', name: 'P-256' },
  { oid: '1.3.132.0.34', name: 'P-384' },
  { oid: '1.3.132.0.35', name: 'P-521' },
  { oid: '1.2.840.113549.1.1.1', name: 'RSA' },
];

const SIGNING_ALG_OPTIONS = [
  { oid: '1.2.840.10045.4.3.2', name: 'ECDSA-SHA256' },
  { oid: '1.2.840.10045.4.3.3', name: 'ECDSA-SHA384' },
  { oid: '1.2.840.10045.4.3.4', name: 'ECDSA-SHA512' },
  { oid: '2.16.840.1.101.3.4.3.1', name: 'DSA-SHA224' },
  { oid: '2.16.840.1.101.3.4.3.2', name: 'DSA-SHA256' },
  { oid: '1.2.840.113549.1.1.11', name: 'RSA-SHA256' },
];

function OidSelectField({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: { oid: string; name: string }[];
  onChange: (oid: string) => void;
}) {
  return (
    <div>
      <label className="text-xs text-gray-500">{label}</label>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full mt-0.5 px-2 py-1 text-xs border border-gray-300 rounded bg-white focus:outline-none focus:ring-2 focus:ring-blue-400"
      >
        {options.map((o) => (
          <option key={o.oid} value={o.oid}>
            {o.oid} ({o.name})
          </option>
        ))}
      </select>
    </div>
  );
}

interface Props {
  onDecode: (hex: string) => void;
  onControl: (hex: string) => void;
  prefillInput: UicBarcodeTicket | null;
  onPrefillConsumed: () => void;
}

function getDefaultTicket(): UicBarcodeTicket {
  const now = new Date();
  const dayOfYear = Math.floor(
    (now.getTime() - new Date(now.getFullYear(), 0, 0).getTime()) / 86400000,
  );
  return {
    format: 'U2',
    level2SignedData: {
      level1Data: {
        securityProviderNum: 9999,
        keyId: 1,
        dataSequence: [{
          dataFormat: 'FCB3',
          decoded: {
            issuingDetail: {
              issuerNum: 9999,
              issuingYear: now.getFullYear(),
              issuingDay: dayOfYear,
              specimen: true,
              securePaperTicket: false,
              activated: true,
            },
            transportDocument: [
              { ticket: { key: 'openTicket', value: { returnIncluded: false } } },
            ],
          },
        }],
      },
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

export default function EncodeTab({ onDecode, onControl, prefillInput, onPrefillConsumed }: Props) {
  const [ticket, setTicket] = useState<UicBarcodeTicket>(getDefaultTicket);

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

  // Prefill-sourced L2 public key (shown when no L2 private key is loaded)
  const [prefillL2PubKeyHex, setPrefillL2PubKeyHex] = useState('');
  const effectiveL2PubKeyHex = l2PubKey || prefillL2PubKeyHex;

  // OID state (editable, auto-filled from curve selection)
  const [l1KeyAlg, setL1KeyAlg] = useState(CURVES['P-256'].keyAlgOid);
  const [l1SigningAlg, setL1SigningAlg] = useState(CURVES['P-256'].sigAlgOid);
  const [l2KeyAlg, setL2KeyAlg] = useState(CURVES['P-256'].keyAlgOid);
  const [l2SigningAlg, setL2SigningAlg] = useState(CURVES['P-256'].sigAlgOid);

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
    ticket: UicBarcodeTicket;
    l1PrivKey: string;
    l1Curve: string;
    l2PrivKey: string;
    l2Curve: string;
    l1KeyAlg: string;
    l1SigningAlg: string;
    l2KeyAlg: string;
    l2SigningAlg: string;
  } | null>(null);

  // -------------------------------------------------------------------------
  // Input change handler - marks signatures as stale
  // -------------------------------------------------------------------------

  const handleInputChange = useCallback((newTicket: UicBarcodeTicket) => {
    setTicket(newTicket);
    // Mark signatures stale when data changes
    if (l1SigHex) setL1SigStale(true);
    if (l2SigHex) setL2SigStale(true);
  }, [l1SigHex, l2SigHex]);

  // Auto-sync OIDs from curve selection
  useEffect(() => {
    const cfg = CURVES[l1Curve as CurveName];
    if (cfg) {
      setL1KeyAlg(cfg.keyAlgOid);
      setL1SigningAlg(cfg.sigAlgOid);
    }
  }, [l1Curve]);

  useEffect(() => {
    const cfg = CURVES[l2Curve as CurveName];
    if (cfg) {
      setL2KeyAlg(cfg.keyAlgOid);
      setL2SigningAlg(cfg.sigAlgOid);
    }
  }, [l2Curve]);

  // Also mark sigs stale when key/curve/OID changes (affects signed data)
  useEffect(() => {
    if (l1SigHex) setL1SigStale(true);
    if (l2SigHex) setL2SigStale(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [l1Curve, l2Curve, l2Enabled, l1KeyAlg, l1SigningAlg, l2KeyAlg, l2SigningAlg, effectiveL2PubKeyHex]);

  // -------------------------------------------------------------------------
  // Apply prefill from decoded ticket
  // -------------------------------------------------------------------------

  useEffect(() => {
    if (prefillInput) {
      setTicket(prefillInput);
      const l1 = prefillInput.level2SignedData.level1Data;
      const l2d = prefillInput.level2SignedData.level2Data;
      // Enable L2 if prefill has dynamic data or L2 fields
      if (l2d || l1.level2PublicKey) {
        setL2Enabled(true);
      }
      // Populate OID state from prefilled input
      if (l1.level1KeyAlg) setL1KeyAlg(l1.level1KeyAlg);
      if (l1.level1SigningAlg) setL1SigningAlg(l1.level1SigningAlg);
      if (l1.level2KeyAlg) setL2KeyAlg(l1.level2KeyAlg);
      if (l1.level2SigningAlg) setL2SigningAlg(l1.level2SigningAlg);
      // Populate L2 public key from prefill (shown even without an L2 private key)
      if (l1.level2PublicKey && l1.level2PublicKey.length > 0) {
        setPrefillL2PubKeyHex(bytesToHex(l1.level2PublicKey));
      } else {
        setPrefillL2PubKeyHex('');
      }
      // Populate signatures from prefilled input if present
      const l1Sig = prefillInput.level2SignedData.level1Signature;
      if (l1Sig && l1Sig.length > 0) {
        setL1SigHex(bytesToHex(l1Sig));
      } else {
        setL1SigHex('');
      }
      setL1SigStale(false);
      const l2Sig = prefillInput.level2Signature;
      if (l2Sig && l2Sig.length > 0) {
        setL2SigHex(bytesToHex(l2Sig));
      } else {
        setL2SigHex('');
      }
      setL2SigStale(false);
      onPrefillConsumed();
    }
  }, [prefillInput, onPrefillConsumed]);

  // -------------------------------------------------------------------------
  // Build a prepared ticket with OIDs and L2 public key set
  // -------------------------------------------------------------------------

  const buildPreparedTicket = useCallback((): UicBarcodeTicket => {
    const l1 = ticket.level2SignedData.level1Data;
    const preparedL1 = {
      ...l1,
      level1KeyAlg: l1KeyAlg,
      level1SigningAlg: l1SigningAlg,
      ...(l2Enabled && effectiveL2PubKeyHex ? {
        level2KeyAlg: l2KeyAlg,
        level2SigningAlg: l2SigningAlg,
        level2PublicKey: hexToBytes(effectiveL2PubKeyHex),
      } : {}),
    };
    return {
      ...ticket,
      level2SignedData: {
        ...ticket.level2SignedData,
        level1Data: preparedL1,
      },
    };
  }, [ticket, l1KeyAlg, l1SigningAlg, l2Enabled, l2KeyAlg, l2SigningAlg, effectiveL2PubKeyHex]);

  // -------------------------------------------------------------------------
  // Generate Level 1 signature
  // -------------------------------------------------------------------------

  const handleGenerateL1Sig = useCallback(() => {
    try {
      const prepared = buildPreparedTicket();
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
  }, [buildPreparedTicket, l1PrivKey, l1Curve, l2SigHex]);

  // -------------------------------------------------------------------------
  // Generate Level 2 signature
  // -------------------------------------------------------------------------

  const handleGenerateL2Sig = useCallback(() => {
    if (!l1SigHex) {
      setL2SigError('Level 1 signature must be generated first');
      return;
    }
    try {
      const prepared = buildPreparedTicket();
      const withL1Sig: UicBarcodeTicket = {
        ...prepared,
        level2SignedData: {
          ...prepared.level2SignedData,
          level1Signature: hexToBytes(l1SigHex),
        },
      };
      const sig = signLevel2Data(withL1Sig, l2PrivKey, l2Curve);
      const sigHex = bytesToHex(sig);
      setL2SigHex(sigHex);
      setL2SigStale(false);
      setL2SigError(null);
    } catch (e) {
      setL2SigError(e instanceof Error ? e.message : 'Failed to generate L2 signature');
    }
  }, [buildPreparedTicket, l1SigHex, l2PrivKey, l2Curve]);

  // -------------------------------------------------------------------------
  // Encode ticket with existing signatures
  // -------------------------------------------------------------------------

  const l2Data = ticket.level2SignedData.level2Data;
  const hasDynamic = !!l2Data;

  const handleEncode = useCallback(() => {
    try {
      const prepared = buildPreparedTicket();
      const withSigs: UicBarcodeTicket = {
        ...prepared,
        level2SignedData: {
          ...prepared.level2SignedData,
          level1Signature: l1SigHex ? hexToBytes(l1SigHex) : new Uint8Array(0),
        },
        level2Signature: l2SigHex ? hexToBytes(l2SigHex) : undefined,
      };

      const encodedBytes = encodeTicket(withSigs);
      const encodedHex = bytesToHex(encodedBytes);
      setHex(encodedHex);
      setBytes(encodedBytes);
      setEncodeError(null);
      window.history.replaceState(null, '', `#encode&hex=${encodedHex}`);

      // Start dynamic refresh countdown if enabled
      if (l2Enabled && dynamicRefreshEnabled && hasDynamic && l1PrivKey && l2PrivKey) {
        regenRef.current = { ticket, l1PrivKey, l1Curve, l2PrivKey, l2Curve, l1KeyAlg, l1SigningAlg, l2KeyAlg, l2SigningAlg };
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
  }, [buildPreparedTicket, l1SigHex, l2SigHex, l2Enabled, dynamicRefreshEnabled, hasDynamic, ticket, l1PrivKey, l1Curve, l2PrivKey, l2Curve, l1KeyAlg, l1SigningAlg, l2KeyAlg, l2SigningAlg, dynamicRefreshInterval]);

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
            const curL2Data = params.ticket.level2SignedData.level2Data;
            const isFdc1 = curL2Data?.dataFormat === 'FDC1';

            let updatedTicket: UicBarcodeTicket;
            if (isFdc1) {
              // FDC1: day is absolute day-of-year (1-366), time is seconds since midnight UTC
              const fdc1Day = utcDayOfYear(now);
              const fdc1Time = now.getUTCHours() * 3600 + now.getUTCMinutes() * 60 + now.getUTCSeconds();
              updatedTicket = {
                ...params.ticket,
                level2SignedData: {
                  ...params.ticket.level2SignedData,
                  level2Data: {
                    ...curL2Data!,
                    decoded: {
                      ...(curL2Data!.decoded as UicDynamicContentData),
                      dynamicContentTimeStamp: {
                        day: fdc1Day,
                        time: fdc1Time,
                      },
                    },
                  },
                },
              };
            } else {
              // Intercode: day is offset from issuing date (UTC) to local date, time is local seconds since midnight
              const iss = getIss(params.ticket);
              const issuingDateNum = Date.UTC(iss!.issuingYear, 0, iss!.issuingDay);
              const localDateNum = Date.UTC(now.getFullYear(), now.getMonth(), now.getDate());
              const dayOffset = Math.floor((localDateNum - issuingDateNum) / 86400_000);
              const localSeconds = now.getHours() * 3600 + now.getMinutes() * 60 + now.getSeconds();
              const utcOffsetQH = Math.round(now.getTimezoneOffset() / 15);
              const dd = curL2Data!.decoded as IntercodeDynamicData;
              updatedTicket = {
                ...params.ticket,
                level2SignedData: {
                  ...params.ticket.level2SignedData,
                  level2Data: {
                    ...curL2Data!,
                    decoded: {
                      ...dd,
                      dynamicContentDay: dayOffset,
                      dynamicContentTime: localSeconds,
                      dynamicContentUTCOffset: utcOffsetQH,
                    },
                  },
                },
              };
            }
            regenRef.current = { ...params, ticket: updatedTicket };
            setTicket(updatedTicket);

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
              const refreshedBytes = signTicket(updatedTicket, level1Key, level2Key);
              const refreshedHex = bytesToHex(refreshedBytes);
              setHex(refreshedHex);
              setBytes(refreshedBytes);
              window.history.replaceState(null, '', `#encode&hex=${refreshedHex}`);
              // Update signature fields to match
              const prepTicket: UicBarcodeTicket = {
                ...updatedTicket,
                level2SignedData: {
                  ...updatedTicket.level2SignedData,
                  level1Data: {
                    ...updatedTicket.level2SignedData.level1Data,
                    level1KeyAlg: params.l1KeyAlg,
                    level1SigningAlg: params.l1SigningAlg,
                    level2KeyAlg: params.l2KeyAlg,
                    level2SigningAlg: params.l2SigningAlg,
                    level2PublicKey: level2Key.publicKey,
                  },
                },
              };
              const l1Sig = signLevel1Data(prepTicket, params.l1PrivKey, params.l1Curve);
              setL1SigHex(bytesToHex(l1Sig));
              setL1SigStale(false);
              const withL1Sig: UicBarcodeTicket = {
                ...prepTicket,
                level2SignedData: {
                  ...prepTicket.level2SignedData,
                  level1Signature: l1Sig,
                },
              };
              const l2Sig = signLevel2Data(withL1Sig, params.l2PrivKey, params.l2Curve);
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
      regenRef.current = { ticket, l1PrivKey, l1Curve, l2PrivKey, l2Curve, l1KeyAlg, l1SigningAlg, l2KeyAlg, l2SigningAlg };
    }
  }, [ticket, l1PrivKey, l1Curve, l2PrivKey, l2Curve, l1KeyAlg, l1SigningAlg, l2KeyAlg, l2SigningAlg]);

  // Stop regeneration when L2 is disabled or dynamic refresh is turned off
  useEffect(() => {
    if (!l2Enabled || !dynamicRefreshEnabled || !hasDynamic) {
      regenRef.current = null;
      setCountdown(null);
    }
  }, [l2Enabled, dynamicRefreshEnabled, hasDynamic]);

  // -------------------------------------------------------------------------
  // Dynamic data update helper
  // -------------------------------------------------------------------------

  const updateDynamicData = useCallback((partial: Partial<IntercodeDynamicData>) => {
    const curL2Data = ticket.level2SignedData.level2Data;
    const dd = curL2Data?.decoded as IntercodeDynamicData | undefined;
    handleInputChange({
      ...ticket,
      level2SignedData: {
        ...ticket.level2SignedData,
        level2Data: {
          ...curL2Data!,
          decoded: { ...dd!, ...partial },
        },
      },
    });
  }, [ticket, handleInputChange]);

  // -------------------------------------------------------------------------
  // Misc helpers
  // -------------------------------------------------------------------------

  const copyHex = () => {
    navigator.clipboard.writeText(hex);
  };

  const jsonPreview = useMemo(() => jsonReplacer
    ? JSON.stringify(ticket, jsonReplacer, 2)
    : JSON.stringify(ticket, null, 2),
  [ticket]);

  const copyJson = () => {
    navigator.clipboard.writeText(jsonPreview);
  };

  const dynamicFormat: 'intercode' | 'fdc1' = l2Data?.dataFormat === 'FDC1' ? 'fdc1' : 'intercode';
  const l2KeyPresent = l2Enabled && !!l2PrivKey;

  // Computed times for display
  const issuingTime = useMemo(() => computeIssuingTime(ticket), [ticket]);
  const endOfValidity = useMemo(() => computeEndOfValidity(ticket), [ticket]);
  const dynamicTime = useMemo(() =>
    dynamicFormat === 'fdc1' ? computeFdc1Time(ticket) : computeIntercodeTime(ticket),
  [ticket, dynamicFormat]);

  const intercodeDecoded = dynamicFormat === 'intercode' ? l2Data?.decoded as IntercodeDynamicData | undefined : undefined;
  const fdc1Decoded = dynamicFormat === 'fdc1' ? l2Data?.decoded as UicDynamicContentData | undefined : undefined;

  return (
    <div className="space-y-6">
      {/* ================================================================= */}
      {/* KEYS SECTION                                                      */}
      {/* ================================================================= */}
      <div className="bg-white rounded-lg border border-gray-200 p-4 space-y-4">
        <h3 className="text-sm font-semibold text-gray-700 uppercase tracking-wide">
          Keys
        </h3>
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
      </div>

      {/* ================================================================= */}
      {/* LEVEL 1 SECTION                                                   */}
      {/* ================================================================= */}
      <div className="bg-white rounded-lg border border-gray-200 p-4 space-y-4">
        <h3 className="text-sm font-semibold text-gray-700 uppercase tracking-wide">
          Level 1
        </h3>

        {/* Level 1 Data */}
        <TicketForm
          value={ticket}
          onChange={handleInputChange}
          renderAfterKeyId={
            <>
              <OidSelectField
                label="level1KeyAlg"
                value={l1KeyAlg}
                options={KEY_ALG_OPTIONS}
                onChange={setL1KeyAlg}
              />
              <OidSelectField
                label="level1SigningAlg"
                value={l1SigningAlg}
                options={SIGNING_ALG_OPTIONS}
                onChange={setL1SigningAlg}
              />
              <OidSelectField
                label="level2KeyAlg"
                value={l2KeyAlg}
                options={KEY_ALG_OPTIONS}
                onChange={setL2KeyAlg}
              />
              <OidSelectField
                label="level2SigningAlg"
                value={l2SigningAlg}
                options={SIGNING_ALG_OPTIONS}
                onChange={setL2SigningAlg}
              />
              {effectiveL2PubKeyHex && (
                <div className="col-span-2">
                  <label className="text-xs text-gray-500">level2PublicKey</label>
                  <div className="w-full mt-0.5 px-2 py-1 text-xs font-mono bg-gray-50 border border-gray-200 rounded text-gray-600 break-all">
                    {effectiveL2PubKeyHex}
                  </div>
                </div>
              )}
            </>
          }
          renderAfterValidityFields={
            endOfValidity && (
              <div className="col-span-2 text-xs text-gray-400">
                end of validity: <ComputedTimeDisplay date={endOfValidity} />
              </div>
            )
          }
          renderAfterIssuingFields={
            issuingTime && (
              <div className="col-span-2 text-xs text-gray-400">
                issuing time: <ComputedTimeDisplay date={issuingTime} />
              </div>
            )
          }
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
            {/* Level 1 Signature (read-only display) */}
            {l1SigHex && (
              <div>
                <label className="text-xs text-gray-500">level1Signature</label>
                <div className="w-full mt-0.5 px-2 py-1 text-xs font-mono bg-gray-50 border border-gray-200 rounded text-gray-600 break-all max-h-16 overflow-y-auto">
                  {l1SigHex}
                </div>
              </div>
            )}

            {/* level2Data */}
            <ToggleSection
              title="level2Data"
              enabled={hasDynamic}
              onToggle={(v) => {
                if (v) {
                  handleInputChange({
                    ...ticket,
                    level2SignedData: {
                      ...ticket.level2SignedData,
                      level2Data: { dataFormat: 'FDC1', decoded: {} },
                    },
                  });
                } else {
                  handleInputChange({
                    ...ticket,
                    level2SignedData: {
                      ...ticket.level2SignedData,
                      level2Data: undefined,
                    },
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
                        ...ticket,
                        level2SignedData: {
                          ...ticket.level2SignedData,
                          level2Data: { dataFormat: 'FDC1', decoded: {} },
                        },
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
                      const spn = ticket.level2SignedData.level1Data.securityProviderNum ?? 0;
                      handleInputChange({
                        ...ticket,
                        level2SignedData: {
                          ...ticket.level2SignedData,
                          level2Data: {
                            dataFormat: `_${spn}.ID1`,
                            decoded: { rics: spn, dynamicContentDay: 0 } as IntercodeDynamicData,
                          },
                        },
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
                    value={fdc1Decoded?.dynamicContentTimeStamp?.day}
                    onChange={(v) => {
                      const ts = fdc1Decoded?.dynamicContentTimeStamp;
                      handleInputChange({
                        ...ticket,
                        level2SignedData: {
                          ...ticket.level2SignedData,
                          level2Data: {
                            ...l2Data!,
                            decoded: {
                              ...fdc1Decoded,
                              dynamicContentTimeStamp: v != null ? { day: v, time: ts?.time ?? 0 } : undefined,
                            },
                          },
                        },
                      });
                    }}
                    placeholder="Day of year (1-366)"
                  />
                  <NumberField
                    label="dynamicContentTimeStamp.time"
                    value={fdc1Decoded?.dynamicContentTimeStamp?.time}
                    onChange={(v) => {
                      const ts = fdc1Decoded?.dynamicContentTimeStamp;
                      handleInputChange({
                        ...ticket,
                        level2SignedData: {
                          ...ticket.level2SignedData,
                          level2Data: {
                            ...l2Data!,
                            decoded: {
                              ...fdc1Decoded,
                              dynamicContentTimeStamp: v != null ? { day: ts?.day ?? 1, time: v } : undefined,
                            },
                          },
                        },
                      });
                    }}
                    placeholder="Seconds since midnight (0-86399)"
                  />
                  {dynamicTime && (
                    <div className="col-span-2 text-xs text-gray-400">
                      generation time: <ComputedTimeDisplay date={dynamicTime} />
                    </div>
                  )}
                </>
              )}

              {dynamicFormat === 'intercode' && (
                <>
                  <NumberField
                    label="rics (in dataFormat)"
                    value={(() => {
                      const m = l2Data?.dataFormat?.match(/^_(\d+)\.ID1$/);
                      return m ? Number(m[1]) : undefined;
                    })()}
                    onChange={(v) => {
                      handleInputChange({
                        ...ticket,
                        level2SignedData: {
                          ...ticket.level2SignedData,
                          level2Data: {
                            ...l2Data!,
                            dataFormat: `_${v ?? 0}.ID1`,
                          },
                        },
                      });
                    }}
                    placeholder="e.g. 3703"
                  />
                  <NumberField
                    label="dynamicContentDay"
                    value={intercodeDecoded?.dynamicContentDay}
                    onChange={(v) => updateDynamicData({ dynamicContentDay: v })}
                  />
                  <OptionalNumberField
                    label="dynamicContentTime"
                    value={intercodeDecoded?.dynamicContentTime}
                    onChange={(v) => updateDynamicData({ dynamicContentTime: v })}
                  />
                  <OptionalNumberField
                    label="dynamicContentUTCOffset"
                    value={intercodeDecoded?.dynamicContentUTCOffset}
                    onChange={(v) => updateDynamicData({ dynamicContentUTCOffset: v })}
                  />
                  <OptionalNumberField
                    label="dynamicContentDuration"
                    value={intercodeDecoded?.dynamicContentDuration}
                    onChange={(v) => updateDynamicData({ dynamicContentDuration: v })}
                  />
                  {dynamicTime && (
                    <div className="col-span-2 text-xs text-gray-400">
                      generation time: <ComputedTimeDisplay date={dynamicTime} utcOffsetQuarterHours={intercodeDecoded?.dynamicContentUTCOffset} />
                    </div>
                  )}
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
                <button
                  onClick={() => onControl(hex)}
                  className="text-xs text-green-600 hover:text-green-800 px-2 py-1 rounded hover:bg-green-50"
                >
                  Control this ticket
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
