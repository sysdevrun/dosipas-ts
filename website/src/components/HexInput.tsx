import { useRef } from 'react';
import {
  SAMPLE_TICKET_HEX,
  SNCF_TER_TICKET_HEX,
  SOLEA_TICKET_HEX,
  CTS_TICKET_HEX,
  GRAND_EST_U1_FCB3_HEX,
} from 'dosipas-ts';
import { scanFromImageFile } from '../lib/scanner';
import { bytesToHex } from '../lib/signing';

const PREFILLS = [
  { label: 'Sample', hex: SAMPLE_TICKET_HEX },
  { label: 'SNCF TER', hex: SNCF_TER_TICKET_HEX },
  { label: 'Solea', hex: SOLEA_TICKET_HEX },
  { label: 'CTS', hex: CTS_TICKET_HEX },
  { label: 'Grand Est', hex: GRAND_EST_U1_FCB3_HEX },
];

interface Props {
  value: string;
  onChange: (hex: string) => void;
  onOpenCamera: () => void;
}

export default function HexInput({ value, onChange, onOpenCamera }: Props) {
  const fileRef = useRef<HTMLInputElement>(null);

  const handleFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const bytes = await scanFromImageFile(file);
      if (bytes) {
        onChange(bytesToHex(bytes));
      } else {
        alert('No Aztec barcode found in image');
      }
    } catch (err) {
      alert(`Scan failed: ${err instanceof Error ? err.message : err}`);
    }
    e.target.value = '';
  };

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2">
        {PREFILLS.map((p) => (
          <button
            key={p.label}
            onClick={() => onChange(p.hex)}
            className="px-3 py-1 text-xs font-medium rounded-full bg-gray-200 text-gray-700 hover:bg-gray-300 transition-colors"
          >
            {p.label}
          </button>
        ))}
        <button
          onClick={() => fileRef.current?.click()}
          className="px-3 py-1 text-xs font-medium rounded-full bg-blue-100 text-blue-700 hover:bg-blue-200 transition-colors"
        >
          Scan image
        </button>
        <button
          onClick={onOpenCamera}
          className="px-3 py-1 text-xs font-medium rounded-full bg-blue-100 text-blue-700 hover:bg-blue-200 transition-colors"
        >
          Camera
        </button>
        <input
          ref={fileRef}
          type="file"
          accept="image/*"
          onChange={handleFile}
          className="hidden"
        />
      </div>
      <textarea
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder="Paste hex-encoded ticket data or click a prefill button..."
        className="w-full h-32 p-3 font-mono text-xs bg-white border border-gray-300 rounded-lg resize-y focus:outline-none focus:ring-2 focus:ring-blue-400 focus:border-transparent"
        spellCheck={false}
      />
    </div>
  );
}
