import { useState, useEffect, useCallback } from 'react';
import { decodeTicket } from 'dosipas-ts';
import type { UicBarcodeTicket } from 'dosipas-ts';
import DecodeTab from './components/DecodeTab';
import EncodeTab from './components/EncodeTab';
import ControlTab from './components/ControlTab';

type Tab = 'decode' | 'encode' | 'control';

function getInitialTab(): Tab {
  const hash = window.location.hash;
  if (hash.startsWith('#encode')) return 'encode';
  if (hash.startsWith('#control')) return 'control';
  return 'decode';
}

function buildHash(tab: Tab, hex: string): string {
  const clean = hex.replace(/\s/g, '');
  if (clean.length > 8) {
    return `${tab}&hex=${clean}`;
  }
  return tab;
}

function getInitialHex(): string {
  const hash = window.location.hash;
  const match = hash.match(/[#&]hex=([0-9a-fA-F]+)/);
  return match ? match[1] : '';
}

export default function App() {
  const [tab, setTab] = useState<Tab>(getInitialTab);
  const [sharedHex, setSharedHex] = useState(getInitialHex);
  const [prefillInput, setPrefillInput] = useState<UicBarcodeTicket | null>(null);

  useEffect(() => {
    const onHashChange = () => {
      const hash = window.location.hash;
      const hexMatch = hash.match(/[#&]hex=([0-9a-fA-F]+)/);
      const hex = hexMatch ? hexMatch[1] : '';

      if (hash.startsWith('#encode')) {
        setTab('encode');
        if (hex) {
          setSharedHex(hex);
          tryPrefillEncode(hex);
        }
      } else if (hash.startsWith('#control')) {
        setTab('control');
        if (hex) setSharedHex(hex);
      } else {
        setTab('decode');
        if (hex) setSharedHex(hex);
      }
    };
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  const tryPrefillEncode = useCallback((hex: string) => {
    try {
      setPrefillInput(decodeTicket(hex));
    } catch {
      // Ignore decode errors - encode tab still usable
    }
  }, []);

  // Handle initial load with #encode&hex=...
  useEffect(() => {
    if (tab === 'encode' && sharedHex.replace(/\s/g, '').length > 8) {
      tryPrefillEncode(sharedHex);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const switchToDecode = (hex: string) => {
    setSharedHex(hex);
    setTab('decode');
    window.location.hash = buildHash('decode', hex);
  };

  const switchToControl = (hex: string) => {
    setSharedHex(hex);
    setTab('control');
    window.location.hash = buildHash('control', hex);
  };

  const switchToEncode = (ticket: UicBarcodeTicket) => {
    setPrefillInput(ticket);
    setTab('encode');
    window.location.hash = buildHash('encode', sharedHex);
  };

  const switchTab = (newTab: Tab) => {
    setTab(newTab);
    window.location.hash = buildHash(newTab, sharedHex);
    if (newTab === 'encode' && sharedHex.replace(/\s/g, '').length > 8) {
      tryPrefillEncode(sharedHex);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 text-gray-900">
      <header className="bg-white border-b border-gray-200 sticky top-0 z-10">
        <div className="max-w-5xl mx-auto px-4 py-3 flex items-center gap-6">
          <h1 className="text-lg font-semibold whitespace-nowrap">dosipas-ts</h1>
          <nav className="flex gap-1">
            <button
              onClick={() => switchTab('decode')}
              className={`px-4 py-1.5 rounded-md text-sm font-medium transition-colors ${
                tab === 'decode'
                  ? 'bg-blue-100 text-blue-800'
                  : 'text-gray-600 hover:bg-gray-100'
              }`}
            >
              Decode
            </button>
            <button
              onClick={() => switchTab('encode')}
              className={`px-4 py-1.5 rounded-md text-sm font-medium transition-colors ${
                tab === 'encode'
                  ? 'bg-blue-100 text-blue-800'
                  : 'text-gray-600 hover:bg-gray-100'
              }`}
            >
              Encode
            </button>
            <button
              onClick={() => switchTab('control')}
              className={`px-4 py-1.5 rounded-md text-sm font-medium transition-colors ${
                tab === 'control'
                  ? 'bg-blue-100 text-blue-800'
                  : 'text-gray-600 hover:bg-gray-100'
              }`}
            >
              Control
            </button>
          </nav>
          <a
            href="https://github.com/sysdevrun/dosipas-ts"
            target="_blank"
            rel="noopener noreferrer"
            className="ml-auto text-gray-400 hover:text-gray-700 transition-colors"
            title="GitHub"
          >
            <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>
          </a>
        </div>
      </header>
      <main className="max-w-5xl mx-auto px-4 py-6">
        {tab === 'decode' && (
          <DecodeTab
            initialHex={sharedHex}
            onHexChange={(h) => setSharedHex(h)}
            onEditInEncoder={switchToEncode}
            onControl={switchToControl}
          />
        )}
        {tab === 'encode' && (
          <EncodeTab
            onDecode={switchToDecode}
            onControl={switchToControl}
            prefillInput={prefillInput}
            onPrefillConsumed={() => setPrefillInput(null)}
          />
        )}
        {tab === 'control' && (
          <ControlTab
            initialHex={sharedHex}
            onHexChange={(h) => setSharedHex(h)}
            onDecode={switchToDecode}
            onEditInEncoder={switchToEncode}
          />
        )}
      </main>
      <footer className="border-t border-gray-200 mt-12 py-6 text-center text-xs text-gray-400">
        <a
          href="https://www.sys-dev-run.fr"
          target="_blank"
          rel="noopener noreferrer"
          className="hover:text-gray-600 transition-colors"
        >
          sys-dev-run.fr
        </a>
      </footer>
    </div>
  );
}
