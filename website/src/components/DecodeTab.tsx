import { useState, useEffect } from 'react';
import type { UicBarcodeTicket } from 'dosipas-ts';
import HexInput from './HexInput';
import TicketView from './TicketView';
import SignatureStatus from './SignatureStatus';
import JsonTree from './JsonTree';
import HexViewer from './HexViewer';
import CameraScanner from './CameraScanner';
import { useTicketDecode } from '../hooks/useTicketDecode';

interface Props {
  initialHex: string;
  onHexChange: (hex: string) => void;
  onEditInEncoder: (ticket: UicBarcodeTicket) => void;
  onControl: (hex: string) => void;
}

export default function DecodeTab({ initialHex, onHexChange, onEditInEncoder, onControl }: Props) {
  const [hex, setHex] = useState(initialHex);
  const [showCamera, setShowCamera] = useState(false);
  const [showHexViewer, setShowHexViewer] = useState(false);
  const [showRawJson, setShowRawJson] = useState(false);
  const [trustFipsKey, setTrustFipsKey] = useState(true);
  const { ticket, signatures, signedData, error, loading } = useTicketDecode(hex, trustFipsKey);

  useEffect(() => {
    if (initialHex && initialHex !== hex) {
      setHex(initialHex);
    }
  }, [initialHex]);

  const updateHex = (h: string) => {
    setHex(h);
    onHexChange(h);
    // Update URL hash for sharing
    const clean = h.replace(/\s/g, '');
    if (clean.length > 8) {
      window.history.replaceState(null, '', `#decode&hex=${clean}`);
    }
  };

  const copyHex = () => {
    navigator.clipboard.writeText(hex.replace(/\s/g, ''));
  };

  const handleEditInEncoder = () => {
    if (!ticket) return;
    onEditInEncoder(ticket);
  };

  return (
    <div className="space-y-6">
      <HexInput
        value={hex}
        onChange={updateHex}
        onOpenCamera={() => setShowCamera(true)}
      />

      <label className="flex items-center gap-2 text-xs text-gray-600">
        <input
          type="checkbox"
          checked={trustFipsKey}
          onChange={(e) => setTrustFipsKey(e.target.checked)}
          className="rounded border-gray-300"
        />
        Trust FIPS public key for level 1 as RICS 9999, key id 0
      </label>

      {showCamera && (
        <CameraScanner
          onScan={(h) => {
            updateHex(h);
            setShowCamera(false);
          }}
          onClose={() => setShowCamera(false)}
        />
      )}

      {loading && (
        <div className="text-sm text-gray-500 animate-pulse">Decoding...</div>
      )}

      {error && (
        <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700">
          {error}
        </div>
      )}

      {ticket && (
        <div className="space-y-4">
          <div className="flex flex-wrap gap-2">
            <button
              onClick={handleEditInEncoder}
              className="text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 px-3 py-1.5 rounded-lg transition-colors"
            >
              Edit in Encoder
            </button>
            <button
              onClick={() => onControl(hex.replace(/\s/g, ''))}
              className="text-sm font-medium text-white bg-green-600 hover:bg-green-700 px-3 py-1.5 rounded-lg transition-colors"
            >
              Control
            </button>
            <button
              onClick={copyHex}
              className="text-xs text-gray-500 hover:text-gray-700 px-2 py-1 rounded hover:bg-gray-100"
            >
              Copy hex
            </button>
            <button
              onClick={() => setShowHexViewer(!showHexViewer)}
              className={`text-xs px-2 py-1 rounded ${
                showHexViewer
                  ? 'bg-blue-100 text-blue-700'
                  : 'text-gray-500 hover:text-gray-700 hover:bg-gray-100'
              }`}
            >
              Hex viewer
            </button>
            <button
              onClick={() => setShowRawJson(!showRawJson)}
              className={`text-xs px-2 py-1 rounded ${
                showRawJson
                  ? 'bg-blue-100 text-blue-700'
                  : 'text-gray-500 hover:text-gray-700 hover:bg-gray-100'
              }`}
            >
              Raw JSON
            </button>
          </div>
          <SignatureStatus result={signatures} loading={loading} />

          {showHexViewer && (
            <div className="bg-white rounded-lg border border-gray-200 p-4">
              <HexViewer hex={hex} signedData={signedData} />
            </div>
          )}

          <TicketView ticket={ticket} />

          {showRawJson && (
            <div className="bg-white rounded-lg border border-gray-200 p-4">
              <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">
                Raw Decoded Object
              </h3>
              <JsonTree data={ticket} defaultOpen />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
