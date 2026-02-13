import { useRef, useEffect, useCallback, useState } from 'react';
import { scanFromVideoFrame } from '../lib/scanner';
import { bytesToHex } from '../lib/signing';

interface Props {
  onScan: (hex: string) => void;
  onClose: () => void;
}

export default function CameraScanner({ onScan, onClose }: Props) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const scanningRef = useRef(false);
  const [error, setError] = useState<string | null>(null);

  const stopStream = useCallback(() => {
    streamRef.current?.getTracks().forEach((t) => t.stop());
    streamRef.current = null;
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function start() {
      try {
        const stream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: 'environment' },
        });
        if (cancelled) {
          stream.getTracks().forEach((t) => t.stop());
          return;
        }
        streamRef.current = stream;
        if (videoRef.current) {
          videoRef.current.srcObject = stream;
          videoRef.current.play();
        }
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Camera access denied');
      }
    }

    start();
    return () => {
      cancelled = true;
      stopStream();
    };
  }, [stopStream]);

  useEffect(() => {
    let interval: ReturnType<typeof setInterval>;

    const scan = async () => {
      if (scanningRef.current) return;
      const video = videoRef.current;
      if (!video || video.readyState < 2) return;
      scanningRef.current = true;
      try {
        const result = await scanFromVideoFrame(video);
        if (result) {
          stopStream();
          onScan(bytesToHex(result));
        }
      } catch {
        // Ignore scan errors, keep trying
      } finally {
        scanningRef.current = false;
      }
    };

    interval = setInterval(scan, 500);
    return () => clearInterval(interval);
  }, [onScan, stopStream]);

  return (
    <div className="fixed inset-0 z-50 bg-black/80 flex flex-col items-center justify-center">
      <div className="relative w-full max-w-lg">
        {error ? (
          <div className="bg-white rounded-lg p-6 m-4 text-center">
            <p className="text-red-600 mb-4">{error}</p>
            <button
              onClick={onClose}
              className="px-4 py-2 bg-gray-200 rounded-lg hover:bg-gray-300"
            >
              Close
            </button>
          </div>
        ) : (
          <>
            <video
              ref={videoRef}
              className="w-full rounded-lg"
              playsInline
              muted
            />
            <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
              <div className="w-48 h-48 border-2 border-white/50 rounded-lg" />
            </div>
          </>
        )}
        <button
          onClick={() => {
            stopStream();
            onClose();
          }}
          className="absolute top-2 right-2 w-8 h-8 bg-black/50 text-white rounded-full flex items-center justify-center hover:bg-black/70"
        >
          X
        </button>
      </div>
      <p className="text-white/70 text-sm mt-4">Point camera at an Aztec barcode</p>
    </div>
  );
}
