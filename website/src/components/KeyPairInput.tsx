import { useState, useEffect } from 'react';
import { generateKeyPair, getPublicKey, bytesToHex, CURVES } from '../lib/signing';

interface Props {
  label: string;
  curve: string;
  onCurveChange: (curve: string) => void;
  privateKeyHex: string;
  onPrivateKeyChange: (hex: string) => void;
  publicKeyHex: string;
  onPublicKeyChange: (hex: string) => void;
  /** When provided, shows a "FIPS Test Key" button that loads this P-256 private key. */
  fipsTestKey?: string;
}

export default function KeyPairInput({
  label,
  curve,
  onCurveChange,
  privateKeyHex,
  onPrivateKeyChange,
  publicKeyHex,
  onPublicKeyChange,
  fipsTestKey,
}: Props) {
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!privateKeyHex) {
      onPublicKeyChange('');
      return;
    }
    try {
      const pk = getPublicKey(privateKeyHex, curve);
      onPublicKeyChange(bytesToHex(pk));
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Invalid key');
      onPublicKeyChange('');
    }
  }, [privateKeyHex, curve]);

  const handleGenerate = () => {
    const kp = generateKeyPair(curve);
    onPrivateKeyChange(bytesToHex(kp.privateKey));
  };

  const handleLoadFipsTestKey = () => {
    if (fipsTestKey) {
      onCurveChange('P-256');
      onPrivateKeyChange(fipsTestKey);
    }
  };

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-3">
        <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wide">{label}</h4>
        <select
          value={curve}
          onChange={(e) => onCurveChange(e.target.value)}
          className="text-xs border border-gray-300 rounded px-2 py-1 bg-white"
        >
          {Object.keys(CURVES).map((c) => (
            <option key={c} value={c}>{c}</option>
          ))}
        </select>
        <button
          onClick={handleGenerate}
          className="text-xs px-3 py-1 bg-blue-100 text-blue-700 rounded hover:bg-blue-200 transition-colors"
        >
          Generate
        </button>
        {fipsTestKey && (
          <button
            onClick={handleLoadFipsTestKey}
            className="text-xs px-3 py-1 bg-amber-100 text-amber-700 rounded hover:bg-amber-200 transition-colors"
            title="Load NIST FIPS 186-4 ECDSA P-256 test vector key"
          >
            FIPS Test Key
          </button>
        )}
        <span className="text-xs text-gray-400 ml-auto">
          Key: {CURVES[curve]?.keyAlgOid} / Sig: {CURVES[curve]?.sigAlgOid}
        </span>
      </div>

      <div>
        <label className="text-xs text-gray-500">Private key (hex)</label>
        <input
          type="text"
          value={privateKeyHex}
          onChange={(e) => onPrivateKeyChange(e.target.value.replace(/\s/g, ''))}
          placeholder="Enter or generate a private key..."
          className="w-full mt-0.5 px-3 py-1.5 font-mono text-xs bg-white border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent"
          spellCheck={false}
        />
      </div>

      {publicKeyHex && (
        <div>
          <label className="text-xs text-gray-500">Public key (hex, derived)</label>
          <div className="mt-0.5 px-3 py-1.5 font-mono text-xs bg-gray-50 border border-gray-200 rounded-lg text-gray-600 break-all">
            {publicKeyHex}
          </div>
        </div>
      )}

      {error && (
        <p className="text-xs text-red-600">{error}</p>
      )}
    </div>
  );
}
