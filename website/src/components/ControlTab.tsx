import { useState, useEffect } from 'react';
import HexInput from './HexInput';
import CameraScanner from './CameraScanner';
import { useTicketControl } from '../hooks/useTicketControl';
import type { ControlResult, CheckResult, TravelerInfo } from 'dosipas-ts';

interface Props {
  initialHex: string;
  onHexChange: (hex: string) => void;
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
// localStorage helpers for network IDs
// ---------------------------------------------------------------------------

const NETWORK_IDS_KEY = 'control-expected-network-ids';

function loadNetworkIds(): string[] {
  try {
    const raw = localStorage.getItem(NETWORK_IDS_KEY);
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    if (Array.isArray(parsed) && parsed.every((v) => typeof v === 'string')) {
      return parsed as string[];
    }
  } catch { /* ignore corrupt data */ }
  return [];
}

function saveNetworkIds(ids: string[]) {
  localStorage.setItem(NETWORK_IDS_KEY, JSON.stringify(ids));
}

// ---------------------------------------------------------------------------
// Network IDs editor
// ---------------------------------------------------------------------------

function NetworkIdsEditor({
  networkIds,
  onChange,
}: {
  networkIds: string[];
  onChange: (ids: string[]) => void;
}) {
  const [draft, setDraft] = useState('');
  const [validationError, setValidationError] = useState<string | null>(null);

  const addId = () => {
    const clean = draft.replace(/\s/g, '').toLowerCase();
    if (!/^[0-9a-f]{6}$/.test(clean)) {
      setValidationError('Must be exactly 3 bytes (6 hex characters)');
      return;
    }
    if (networkIds.includes(clean)) {
      setValidationError('Already added');
      return;
    }
    const next = [...networkIds, clean];
    onChange(next);
    setDraft('');
    setValidationError(null);
  };

  const removeId = (id: string) => {
    onChange(networkIds.filter((v) => v !== id));
  };

  return (
    <div className="space-y-2">
      <p className="text-xs text-gray-500">
        Expected Intercode network IDs (3 bytes, hex)
      </p>
      <div className="flex gap-2">
        <input
          type="text"
          value={draft}
          onChange={(e) => {
            setDraft(e.target.value);
            setValidationError(null);
          }}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              e.preventDefault();
              addId();
            }
          }}
          placeholder="e.g. 250502"
          maxLength={6}
          className="flex-1 min-w-0 rounded border border-gray-300 px-2 py-1 text-xs font-mono focus:outline-none focus:ring-1 focus:ring-blue-400"
        />
        <button
          onClick={addId}
          className="text-xs font-medium text-white bg-blue-600 hover:bg-blue-700 px-2.5 py-1 rounded transition-colors"
        >
          Add
        </button>
      </div>
      {validationError && (
        <p className="text-xs text-red-600">{validationError}</p>
      )}
      {networkIds.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {networkIds.map((id) => (
            <span
              key={id}
              className="inline-flex items-center gap-1 bg-blue-50 text-blue-700 text-xs font-mono px-2 py-0.5 rounded"
            >
              {id}
              <button
                onClick={() => removeId(id)}
                className="text-blue-400 hover:text-red-500 font-bold leading-none"
              >
                x
              </button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main ControlTab component
// ---------------------------------------------------------------------------

export default function ControlTab({ initialHex, onHexChange }: Props) {
  const [hex, setHex] = useState(initialHex);
  const [showCamera, setShowCamera] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [trustFipsKey, setTrustFipsKey] = useState(true);
  const [networkIds, setNetworkIds] = useState(loadNetworkIds);
  const { result, error, loading } = useTicketControl(hex, trustFipsKey, networkIds);

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

  const updateNetworkIds = (ids: string[]) => {
    setNetworkIds(ids);
    saveNetworkIds(ids);
  };

  return (
    <div className="space-y-6">
      <HexInput
        value={hex}
        onChange={updateHex}
        onOpenCamera={() => setShowCamera(true)}
      />

      {/* Collapsible Settings section */}
      <details
        open={settingsOpen}
        onToggle={(e) => setSettingsOpen((e.target as HTMLDetailsElement).open)}
      >
        <summary className="cursor-pointer select-none text-xs font-semibold text-gray-500 uppercase tracking-wide hover:text-gray-700">
          Settings
        </summary>
        <div className="mt-3 space-y-4 pl-1">
          <label className="flex items-center gap-2 text-xs text-gray-600">
            <input
              type="checkbox"
              checked={trustFipsKey}
              onChange={(e) => setTrustFipsKey(e.target.checked)}
              className="rounded border-gray-300"
            />
            Trust FIPS public key for level 1 as RICS 9999, key id 0
          </label>

          <NetworkIdsEditor networkIds={networkIds} onChange={updateNetworkIds} />
        </div>
      </details>

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
          <TravelerSection result={result} />
          <ChecksList result={result} />
        </div>
      )}
    </div>
  );
}
