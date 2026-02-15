import { useState, useEffect, useRef } from 'react';
import { controlTicket } from 'dosipas-ts';
import type { ControlResult } from 'dosipas-ts';
import { createKeyProvider } from '../lib/keys';

export interface ControlHookResult {
  result: ControlResult | null;
  error: string | null;
  loading: boolean;
}

export function useTicketControl(hex: string, trustFipsKey = false): ControlHookResult {
  const [result, setResult] = useState<ControlResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const debounceRef = useRef<ReturnType<typeof setTimeout>>(undefined);

  useEffect(() => {
    clearTimeout(debounceRef.current);

    const clean = hex.replace(/\s/g, '');
    if (!clean || clean.length < 8) {
      setResult(null);
      setError(null);
      setLoading(false);
      return;
    }

    setLoading(true);

    debounceRef.current = setTimeout(async () => {
      try {
        const keyProvider = await createKeyProvider(trustFipsKey);
        const controlResult = await controlTicket(clean, {
          level1KeyProvider: keyProvider,
        });
        setResult(controlResult);
        setError(null);
      } catch (e: unknown) {
        setResult(null);
        setError(e instanceof Error ? e.message : 'Control failed');
      } finally {
        setLoading(false);
      }
    }, 200);

    return () => clearTimeout(debounceRef.current);
  }, [hex, trustFipsKey]);

  return { result, error, loading };
}
