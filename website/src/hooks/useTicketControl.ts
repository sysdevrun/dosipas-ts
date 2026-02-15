import { useState, useEffect, useRef } from 'react';
import { controlTicket } from 'dosipas-ts';
import type { ControlResult } from 'dosipas-ts';
import { createKeyProvider } from '../lib/keys';

export interface ControlHookResult {
  result: ControlResult | null;
  error: string | null;
  loading: boolean;
}

export function useTicketControl(
  hex: string,
  trustFipsKey = false,
  expectedNetworkIds: string[] = [],
): ControlHookResult {
  const [result, setResult] = useState<ControlResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const debounceRef = useRef<ReturnType<typeof setTimeout>>(undefined);

  // Stable serialisation so the effect only re-runs when the actual values change
  const networkIdsKey = expectedNetworkIds.slice().sort().join(',');

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
        const ids = networkIdsKey ? networkIdsKey.split(',') : [];
        const controlResult = await controlTicket(clean, {
          level1KeyProvider: keyProvider,
          ...(ids.length > 0 && { expectedIntercodeNetworkIds: new Set(ids) }),
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
  }, [hex, trustFipsKey, networkIdsKey]);

  return { result, error, loading };
}
