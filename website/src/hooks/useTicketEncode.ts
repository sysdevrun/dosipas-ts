import { useState, useCallback } from 'react';
import type { UicBarcodeTicket, CurveName } from 'dosipas-ts';
import {
  signTicket,
  bytesToHex,
  hexToBytes,
  getPublicKey,
  type KeyPair,
} from '../lib/signing';

export interface EncodeResult {
  hex: string;
  bytes: Uint8Array;
  error: string | null;
  loading: boolean;
}

export function useTicketEncode() {
  const [result, setResult] = useState<EncodeResult>({
    hex: '',
    bytes: new Uint8Array(),
    error: null,
    loading: false,
  });

  const encode = useCallback(
    (
      ticket: UicBarcodeTicket,
      level1PrivateKeyHex: string,
      level1Curve: string,
      level2PrivateKeyHex: string,
      level2Curve: string,
    ) => {
      setResult((prev) => ({ ...prev, loading: true, error: null }));

      try {
        const level1Key: KeyPair = {
          privateKey: hexToBytes(level1PrivateKeyHex),
          publicKey: getPublicKey(level1PrivateKeyHex, level1Curve),
          curve: level1Curve as CurveName,
        };

        let level2Key: KeyPair | undefined;
        if (level2PrivateKeyHex) {
          level2Key = {
            privateKey: hexToBytes(level2PrivateKeyHex),
            publicKey: getPublicKey(level2PrivateKeyHex, level2Curve),
            curve: level2Curve as CurveName,
          };
        }

        const bytes = signTicket(ticket, level1Key, level2Key);
        const hex = bytesToHex(bytes);

        setResult({ hex, bytes, error: null, loading: false });
      } catch (e: unknown) {
        setResult({
          hex: '',
          bytes: new Uint8Array(),
          error: e instanceof Error ? e.message : 'Encode failed',
          loading: false,
        });
      }
    },
    [],
  );

  return { ...result, encode };
}
