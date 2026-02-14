import { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import type { UicBarcodeTicketInput } from 'dosipas-ts';
import TicketForm from './TicketForm';
import KeyPairInput from './KeyPairInput';
import AztecBarcode from './AztecBarcode';
import { useTicketEncode } from '../hooks/useTicketEncode';

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

export default function EncodeTab({ onDecode, prefillInput, onPrefillConsumed }: Props) {
  const [input, setInput] = useState<UicBarcodeTicketInput>(getDefaultInput);

  const [l1Curve, setL1Curve] = useState('P-256');
  const [l1PrivKey, setL1PrivKey] = useState('');
  const [l1PubKey, setL1PubKey] = useState('');

  const [l2Enabled, setL2Enabled] = useState(false);
  const [l2Curve, setL2Curve] = useState('P-256');
  const [l2PrivKey, setL2PrivKey] = useState('');
  const [l2PubKey, setL2PubKey] = useState('');

  const [jsonOpen, setJsonOpen] = useState(false);
  const [countdown, setCountdown] = useState<number | null>(null);

  const { hex, bytes, error, loading, encode } = useTicketEncode();

  // Keep mutable refs for the regeneration interval
  const regenRef = useRef<{
    input: UicBarcodeTicketInput;
    l1PrivKey: string;
    l1Curve: string;
    l2PrivKey: string;
    l2Curve: string;
  } | null>(null);

  // Apply prefill from decoded ticket
  useEffect(() => {
    if (prefillInput) {
      setInput(prefillInput);
      onPrefillConsumed();
    }
  }, [prefillInput, onPrefillConsumed]);

  const handleEncode = useCallback(() => {
    if (!l1PrivKey) {
      return;
    }
    if (l2Enabled && !l2PrivKey) {
      return;
    }
    encode(input, l1PrivKey, l1Curve, l2Enabled ? l2PrivKey : '', l2Curve);
    // Store params for regeneration when L2 is enabled
    if (l2Enabled) {
      regenRef.current = { input, l1PrivKey, l1Curve, l2PrivKey, l2Curve };
      setCountdown(10);
    } else {
      regenRef.current = null;
      setCountdown(null);
    }
  }, [input, l1PrivKey, l1Curve, l2Enabled, l2PrivKey, l2Curve, encode]);

  // Level 2 signature regeneration: re-encode every 10 seconds
  useEffect(() => {
    if (countdown === null) return;

    const timer = setInterval(() => {
      setCountdown((prev) => {
        if (prev === null) return null;
        if (prev <= 1) {
          // Time to regenerate
          const params = regenRef.current;
          if (params) {
            encode(
              params.input,
              params.l1PrivKey,
              params.l1Curve,
              params.l2PrivKey,
              params.l2Curve,
            );
          }
          return 10;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [countdown === null, encode]);

  // Update regeneration params when input or keys change (while regeneration is active)
  useEffect(() => {
    if (regenRef.current) {
      regenRef.current = { input, l1PrivKey, l1Curve, l2PrivKey, l2Curve };
    }
  }, [input, l1PrivKey, l1Curve, l2PrivKey, l2Curve]);

  // Stop regeneration when L2 is disabled
  useEffect(() => {
    if (!l2Enabled) {
      regenRef.current = null;
      setCountdown(null);
    }
  }, [l2Enabled]);

  const copyHex = () => {
    navigator.clipboard.writeText(hex);
  };

  const jsonPreview = useMemo(() => JSON.stringify(input, jsonReplacer, 2), [input]);

  const copyJson = () => {
    navigator.clipboard.writeText(jsonPreview);
  };

  return (
    <div className="space-y-6">
      {/* Signing Keys at top */}
      <div className="space-y-4 bg-white rounded-lg border border-gray-200 p-4">
        <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide">
          Signing Keys
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

        <div className="border-t border-gray-100 pt-3">
          <label className="flex items-center gap-2 mb-2">
            <input
              type="checkbox"
              checked={l2Enabled}
              onChange={(e) => setL2Enabled(e.target.checked)}
              className="rounded border-gray-300"
            />
            <span className="text-xs font-semibold text-gray-500 uppercase tracking-wide">
              Enable Level 2 (dynamic barcode)
            </span>
          </label>
          {l2Enabled && (
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
          )}
        </div>
      </div>

      {/* Ticket Form */}
      <TicketForm value={input} onChange={setInput} />

      {/* Encode button */}
      <div className="flex gap-3">
        <button
          onClick={handleEncode}
          disabled={loading || !l1PrivKey || (l2Enabled && !l2PrivKey)}
          className="px-6 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors"
        >
          {loading ? 'Encoding...' : 'Encode & Sign'}
        </button>
      </div>

      {/* Error display */}
      {error && (
        <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700">
          {error}
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
