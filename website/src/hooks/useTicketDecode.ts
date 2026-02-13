import { useState, useEffect, useRef } from 'react';
import { decodeTicket, verifySignatures, extractSignedData } from 'dosipas-ts';
import type {
  UicBarcodeTicket,
  SignatureVerificationResult,
  ExtractedSignedData,
} from 'dosipas-ts';
import { createKeyProvider } from '../lib/keys';

export interface DecodeResult {
  ticket: UicBarcodeTicket | null;
  signatures: SignatureVerificationResult | null;
  signedData: ExtractedSignedData | null;
  error: string | null;
  loading: boolean;
}

export function useTicketDecode(hex: string): DecodeResult {
  const [ticket, setTicket] = useState<UicBarcodeTicket | null>(null);
  const [signatures, setSignatures] = useState<SignatureVerificationResult | null>(null);
  const [signedData, setSignedData] = useState<ExtractedSignedData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const debounceRef = useRef<ReturnType<typeof setTimeout>>(undefined);

  useEffect(() => {
    clearTimeout(debounceRef.current);

    const clean = hex.replace(/\s/g, '');
    if (!clean || clean.length < 8) {
      setTicket(null);
      setSignatures(null);
      setSignedData(null);
      setError(null);
      setLoading(false);
      return;
    }

    setLoading(true);

    debounceRef.current = setTimeout(async () => {
      try {
        const decoded = decodeTicket(clean);
        setTicket(decoded);
        setError(null);

        // Extract signed data for hex viewer
        try {
          const bytes = new Uint8Array(
            clean.match(/.{1,2}/g)!.map((b) => parseInt(b, 16)),
          );
          const extracted = extractSignedData(bytes);
          setSignedData(extracted);
        } catch {
          setSignedData(null);
        }

        // Verify signatures in background
        try {
          const bytes = new Uint8Array(
            clean.match(/.{1,2}/g)!.map((b) => parseInt(b, 16)),
          );
          const keyProvider = await createKeyProvider();
          const result = await verifySignatures(bytes, {
            level1KeyProvider: keyProvider,
          });
          setSignatures(result);
        } catch {
          setSignatures(null);
        }
      } catch (e: unknown) {
        setTicket(null);
        setSignatures(null);
        setSignedData(null);
        setError(e instanceof Error ? e.message : 'Decode failed');
      } finally {
        setLoading(false);
      }
    }, 200);

    return () => clearTimeout(debounceRef.current);
  }, [hex]);

  return { ticket, signatures, signedData, error, loading };
}
