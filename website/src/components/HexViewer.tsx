import type { ExtractedSignedData } from 'dosipas-ts';

interface Props {
  hex: string;
  signedData: ExtractedSignedData | null;
}

interface Region {
  start: number;
  end: number;
  label: string;
  color: string;
}

function findSubarray(haystack: Uint8Array, needle: Uint8Array): number {
  if (needle.length === 0) return -1;
  outer: for (let i = 0; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

export default function HexViewer({ hex, signedData }: Props) {
  const clean = hex.replace(/\s/g, '');
  if (clean.length < 2) return null;

  const bytes = new Uint8Array(
    clean.match(/.{1,2}/g)!.map((b) => parseInt(b, 16)),
  );

  const regions: Region[] = [];

  if (signedData) {
    const l1Idx = findSubarray(bytes, signedData.level1DataBytes);
    if (l1Idx >= 0) {
      regions.push({
        start: l1Idx,
        end: l1Idx + signedData.level1DataBytes.length,
        label: 'L1 data',
        color: 'bg-blue-100 text-blue-900',
      });
    }

    const l2Idx = findSubarray(bytes, signedData.level2SignedBytes);
    if (l2Idx >= 0) {
      regions.push({
        start: l2Idx,
        end: l2Idx + signedData.level2SignedBytes.length,
        label: 'L2 signed',
        color: 'bg-green-100 text-green-900',
      });
    }

    if (signedData.security.level1Signature) {
      const sigIdx = findSubarray(bytes, signedData.security.level1Signature);
      if (sigIdx >= 0) {
        regions.push({
          start: sigIdx,
          end: sigIdx + signedData.security.level1Signature.length,
          label: 'L1 sig',
          color: 'bg-orange-100 text-orange-900',
        });
      }
    }

    if (signedData.security.level2Signature) {
      const sigIdx = findSubarray(bytes, signedData.security.level2Signature);
      if (sigIdx >= 0) {
        regions.push({
          start: sigIdx,
          end: sigIdx + signedData.security.level2Signature.length,
          label: 'L2 sig',
          color: 'bg-purple-100 text-purple-900',
        });
      }
    }
  }

  function getRegion(byteIdx: number): Region | undefined {
    // Return the most specific (smallest) matching region
    let best: Region | undefined;
    for (const r of regions) {
      if (byteIdx >= r.start && byteIdx < r.end) {
        if (!best || (r.end - r.start) < (best.end - best.start)) {
          best = r;
        }
      }
    }
    return best;
  }

  // Render in rows of 16 bytes
  const rowCount = Math.ceil(bytes.length / 16);
  const rows: React.ReactElement[] = [];

  for (let row = 0; row < rowCount; row++) {
    const offset = row * 16;
    const cells: React.ReactElement[] = [];

    for (let col = 0; col < 16; col++) {
      const idx = offset + col;
      if (idx >= bytes.length) {
        cells.push(<span key={col} className="w-6 inline-block">&nbsp;</span>);
        continue;
      }
      const region = getRegion(idx);
      const hexByte = bytes[idx].toString(16).padStart(2, '0');
      cells.push(
        <span
          key={col}
          className={`w-6 inline-block text-center rounded-xs ${region?.color ?? ''}`}
          title={region?.label}
        >
          {hexByte}
        </span>,
      );
    }

    rows.push(
      <div key={row} className="flex gap-0.5">
        <span className="w-12 text-gray-400 text-right mr-2 shrink-0">
          {offset.toString(16).padStart(4, '0')}
        </span>
        {cells}
      </div>,
    );
  }

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-2 text-xs">
        {regions.map((r) => (
          <span key={r.label} className={`px-2 py-0.5 rounded ${r.color}`}>
            {r.label}
          </span>
        ))}
      </div>
      <div className="font-mono text-xs leading-5 overflow-x-auto">{rows}</div>
    </div>
  );
}
