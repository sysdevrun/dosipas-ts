import { useState } from 'react';

interface Props {
  data: unknown;
  label?: string;
  defaultOpen?: boolean;
}

function isObject(val: unknown): val is Record<string, unknown> {
  return val !== null && typeof val === 'object' && !ArrayBuffer.isView(val);
}

function formatValue(val: unknown): string {
  if (val instanceof Uint8Array || val instanceof ArrayBuffer) {
    const arr = val instanceof Uint8Array ? val : new Uint8Array(val);
    if (arr.length <= 32) {
      return Array.from(arr)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join(' ');
    }
    return `[${arr.length} bytes]`;
  }
  if (typeof val === 'string') return `"${val}"`;
  if (typeof val === 'boolean') return val ? 'true' : 'false';
  if (typeof val === 'number') return String(val);
  if (val === null) return 'null';
  if (val === undefined) return 'undefined';
  return String(val);
}

function JsonNode({ data, label, defaultOpen = false }: Props) {
  const [open, setOpen] = useState(defaultOpen);

  if (Array.isArray(data)) {
    if (data.length === 0) {
      return (
        <div className="ml-4">
          {label && <span className="text-gray-500">{label}: </span>}
          <span className="text-gray-400">[]</span>
        </div>
      );
    }
    return (
      <div className="ml-4">
        <button
          onClick={() => setOpen(!open)}
          className="text-left hover:bg-gray-100 rounded px-0.5 -ml-0.5"
        >
          <span className="text-gray-400 text-xs w-4 inline-block">{open ? '\u25BC' : '\u25B6'}</span>
          {label && <span className="text-gray-500">{label}: </span>}
          <span className="text-gray-400">[{data.length}]</span>
        </button>
        {open && (
          <div>
            {data.map((item, i) => (
              <JsonNode key={i} data={item} label={String(i)} />
            ))}
          </div>
        )}
      </div>
    );
  }

  if (isObject(data)) {
    const entries = Object.entries(data);
    if (entries.length === 0) {
      return (
        <div className="ml-4">
          {label && <span className="text-gray-500">{label}: </span>}
          <span className="text-gray-400">{'{}'}</span>
        </div>
      );
    }
    return (
      <div className="ml-4">
        <button
          onClick={() => setOpen(!open)}
          className="text-left hover:bg-gray-100 rounded px-0.5 -ml-0.5"
        >
          <span className="text-gray-400 text-xs w-4 inline-block">{open ? '\u25BC' : '\u25B6'}</span>
          {label && <span className="text-gray-500">{label}: </span>}
          <span className="text-gray-400">{`{${entries.length}}`}</span>
        </button>
        {open && (
          <div>
            {entries.map(([key, val]) => (
              <JsonNode key={key} data={val} label={key} />
            ))}
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="ml-4">
      {label && <span className="text-gray-500">{label}: </span>}
      <span className={data === undefined ? "text-blue-400" : "text-blue-700"}>{formatValue(data)}</span>
    </div>
  );
}

export default function JsonTree({ data, label, defaultOpen = true }: Props) {
  return (
    <div className="font-mono text-xs overflow-x-auto">
      <JsonNode data={data} label={label} defaultOpen={defaultOpen} />
    </div>
  );
}
