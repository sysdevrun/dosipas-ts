import { useState, useEffect } from 'react';
import type { UicBarcodeTicketInput } from 'dosipas-ts';
import HexInput from './HexInput';
import CameraScanner from './CameraScanner';
import { useTicketControl } from '../hooks/useTicketControl';
import { ticketToInput } from '../lib/convert';
import type { ControlResult, CheckResult, TravelerInfo } from 'dosipas-ts';

interface Props {
  initialHex: string;
  onHexChange: (hex: string) => void;
  onDecode: (hex: string) => void;
  onEditInEncoder: (input: UicBarcodeTicketInput) => void;
}

// ---------------------------------------------------------------------------
// Check badge component
// ---------------------------------------------------------------------------

function CheckBadge({ check }: { check: CheckResult }) {
  let bg: string;
  let text: string;
  let icon: string;

  if (check.passed) {
    if (check.severity === 'info') {
      bg = 'bg-gray-100';
      text = 'text-gray-600';
      icon = 'i';
    } else {
      bg = 'bg-green-100';
      text = 'text-green-800';
      icon = '\u2713';
    }
  } else {
    if (check.severity === 'error') {
      bg = 'bg-red-100';
      text = 'text-red-800';
      icon = '\u2717';
    } else if (check.severity === 'warning') {
      bg = 'bg-amber-100';
      text = 'text-amber-800';
      icon = '!';
    } else {
      bg = 'bg-gray-100';
      text = 'text-gray-600';
      icon = 'i';
    }
  }

  return (
    <div className={`flex items-start gap-2 px-3 py-2 rounded-lg ${bg}`}>
      <span className={`font-bold text-sm mt-0.5 ${text} w-4 text-center shrink-0`}>{icon}</span>
      <div className="min-w-0">
        <span className={`text-sm font-medium ${text}`}>{check.name}</span>
        {check.message && (
          <p className={`text-xs mt-0.5 ${text} opacity-80`}>{check.message}</p>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Overall status banner
// ---------------------------------------------------------------------------

function StatusBanner({ result }: { result: ControlResult }) {
  const checks = Object.values(result.checks) as CheckResult[];
  const errorCount = checks.filter(
    (c: CheckResult) => c.severity === 'error' && !c.passed,
  ).length;
  const warningCount = checks.filter(
    (c: CheckResult) => c.severity === 'warning' && !c.passed,
  ).length;

  if (result.valid) {
    return (
      <div className="p-4 bg-green-50 border border-green-200 rounded-xl flex items-center gap-3">
        <div className="w-10 h-10 rounded-full bg-green-500 flex items-center justify-center shrink-0">
          <span className="text-white text-xl font-bold">{'\u2713'}</span>
        </div>
        <div>
          <p className="text-green-800 font-semibold text-lg">Valid</p>
          <p className="text-green-700 text-sm">
            All checks passed
            {warningCount > 0 && ` (${warningCount} warning${warningCount > 1 ? 's' : ''})`}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-4 bg-red-50 border border-red-200 rounded-xl flex items-center gap-3">
      <div className="w-10 h-10 rounded-full bg-red-500 flex items-center justify-center shrink-0">
        <span className="text-white text-xl font-bold">{'\u2717'}</span>
      </div>
      <div>
        <p className="text-red-800 font-semibold text-lg">Invalid</p>
        <p className="text-red-700 text-sm">
          {errorCount} error{errorCount > 1 ? 's' : ''}
          {warningCount > 0 && `, ${warningCount} warning${warningCount > 1 ? 's' : ''}`}
        </p>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Traveler info display
// ---------------------------------------------------------------------------

function formatBirthdate(traveler: TravelerInfo): string | null {
  if (traveler.dateOfBirth) return traveler.dateOfBirth;

  const parts: string[] = [];
  if (traveler.yearOfBirth != null) {
    if (traveler.monthOfBirth != null && traveler.dayOfBirthInMonth != null) {
      parts.push(
        `${traveler.yearOfBirth}-${String(traveler.monthOfBirth).padStart(2, '0')}-${String(traveler.dayOfBirthInMonth).padStart(2, '0')}`,
      );
    } else if (traveler.monthOfBirth != null) {
      parts.push(`${traveler.yearOfBirth}-${String(traveler.monthOfBirth).padStart(2, '0')}`);
    } else if (traveler.dayOfBirth != null) {
      parts.push(`${traveler.yearOfBirth}, day ${traveler.dayOfBirth}`);
    } else {
      parts.push(String(traveler.yearOfBirth));
    }
  }
  return parts.length > 0 ? parts.join('') : null;
}

function formatName(traveler: TravelerInfo): string {
  const parts: string[] = [];
  if (traveler.firstName) parts.push(traveler.firstName);
  if (traveler.secondName) parts.push(traveler.secondName);
  if (traveler.lastName) parts.push(traveler.lastName);
  return parts.join(' ') || '(unnamed)';
}

function TravelerCard({ traveler, index }: { traveler: TravelerInfo; index: number }) {
  const name = formatName(traveler);
  const birthdate = formatBirthdate(traveler);
  const isHolder = traveler.ticketHolder !== false;

  return (
    <div className="flex items-center gap-3 px-4 py-3 bg-white rounded-lg border border-gray-200">
      <div className="w-8 h-8 rounded-full bg-blue-100 flex items-center justify-center shrink-0">
        <span className="text-blue-700 text-sm font-semibold">{index + 1}</span>
      </div>
      <div className="min-w-0">
        <p className="font-medium text-gray-900">
          {name}
          {isHolder && (
            <span className="ml-2 text-xs bg-blue-100 text-blue-700 px-1.5 py-0.5 rounded">
              Holder
            </span>
          )}
        </p>
        {birthdate && (
          <p className="text-sm text-gray-500">Born: {birthdate}</p>
        )}
        {traveler.passengerType && (
          <p className="text-xs text-gray-400">{traveler.passengerType}</p>
        )}
      </div>
    </div>
  );
}

function TravelerSection({ result }: { result: ControlResult }) {
  if (!result.ticket) return null;

  const travelers: TravelerInfo[] = [];
  for (const entry of result.ticket.level2SignedData.level1Data.dataSequence) {
    if (entry.decoded?.travelerDetail?.traveler) {
      travelers.push(...entry.decoded.travelerDetail.traveler);
    }
  }

  if (travelers.length === 0) {
    return (
      <div className="bg-white rounded-lg border border-gray-200 p-4">
        <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">
          Ticket Holders
        </h3>
        <p className="text-sm text-gray-400 italic">No traveler data in ticket</p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide">
        Ticket Holders
      </h3>
      {travelers.map((t, i) => (
        <TravelerCard key={i} traveler={t} index={i} />
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Checks list
// ---------------------------------------------------------------------------

function ChecksList({ result }: { result: ControlResult }) {
  // Group checks by category
  const checks = Object.values(result.checks) as CheckResult[];
  const errorChecks = checks.filter(
    (c: CheckResult) => c.severity === 'error' && !c.passed,
  );
  const warningChecks = checks.filter(
    (c: CheckResult) => c.severity === 'warning' && !c.passed,
  );
  const passedChecks = checks.filter((c: CheckResult) => c.passed);

  return (
    <div className="space-y-3">
      <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide">
        Validation Checks
      </h3>

      {errorChecks.length > 0 && (
        <div className="space-y-1">
          {errorChecks.map((c, i) => (
            <CheckBadge key={`err-${i}`} check={c} />
          ))}
        </div>
      )}

      {warningChecks.length > 0 && (
        <div className="space-y-1">
          {warningChecks.map((c, i) => (
            <CheckBadge key={`warn-${i}`} check={c} />
          ))}
        </div>
      )}

      {passedChecks.length > 0 && (
        <div className="space-y-1">
          {passedChecks.map((c, i) => (
            <CheckBadge key={`pass-${i}`} check={c} />
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main ControlTab component
// ---------------------------------------------------------------------------

export default function ControlTab({ initialHex, onHexChange, onDecode, onEditInEncoder }: Props) {
  const [hex, setHex] = useState(initialHex);
  const [showCamera, setShowCamera] = useState(false);
  const [trustFipsKey, setTrustFipsKey] = useState(true);
  const { result, error, loading } = useTicketControl(hex, trustFipsKey);

  const handleEditInEncoder = () => {
    if (!result?.ticket) return;
    try {
      const input = ticketToInput(result.ticket);
      onEditInEncoder(input);
    } catch (e) {
      alert(`Cannot convert: ${e instanceof Error ? e.message : e}`);
    }
  };

  useEffect(() => {
    if (initialHex && initialHex !== hex) {
      setHex(initialHex);
    }
  }, [initialHex]);

  const updateHex = (h: string) => {
    setHex(h);
    onHexChange(h);
    const clean = h.replace(/\s/g, '');
    if (clean.length > 8) {
      window.history.replaceState(null, '', `#control&hex=${clean}`);
    }
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
        <div className="text-sm text-gray-500 animate-pulse">Controlling...</div>
      )}

      {error && (
        <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700">
          {error}
        </div>
      )}

      {result && (
        <div className="space-y-4">
          <StatusBanner result={result} />
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => onDecode(hex.replace(/\s/g, ''))}
              className="text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 px-3 py-1.5 rounded-lg transition-colors"
            >
              Decode
            </button>
            <button
              onClick={handleEditInEncoder}
              className="text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 px-3 py-1.5 rounded-lg transition-colors"
            >
              Edit in Encoder
            </button>
          </div>
          <TravelerSection result={result} />
          <ChecksList result={result} />
        </div>
      )}
    </div>
  );
}
