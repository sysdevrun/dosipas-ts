import { useRef, useEffect } from 'react';
import { renderAztec } from '../lib/aztec';

interface Props {
  data: Uint8Array;
}

export default function AztecBarcode({ data }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    if (!canvasRef.current || data.length === 0) return;
    try {
      renderAztec(canvasRef.current, data, 4);
    } catch {
      // bwip-js may fail for certain data
    }
  }, [data]);

  const download = () => {
    if (!canvasRef.current) return;
    const link = document.createElement('a');
    link.download = 'uic-barcode.png';
    link.href = canvasRef.current.toDataURL('image/png');
    link.click();
  };

  return (
    <div className="space-y-2">
      <canvas
        ref={canvasRef}
        className="mx-auto w-full"
        style={{ imageRendering: 'pixelated' }}
      />
      <button
        onClick={download}
        className="text-xs text-gray-500 hover:text-gray-700 px-2 py-1 rounded hover:bg-gray-100"
      >
        Download PNG
      </button>
    </div>
  );
}
