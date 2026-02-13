import type { SignatureVerificationResult } from 'dosipas-ts';

interface Props {
  result: SignatureVerificationResult | null;
  loading: boolean;
}

function Badge({
  valid,
  label,
  algorithm,
  error,
}: {
  valid: boolean;
  label: string;
  algorithm?: string;
  error?: string;
}) {
  const isDsa = error?.toLowerCase().includes('dsa') && !error.toLowerCase().includes('ecdsa');
  const isUnsupported = error?.includes('not supported') || error?.includes('Unsupported');
  const isMissing = error?.includes('No level 1 public key') || error?.includes('Key not found');

  let bg: string;
  let text: string;
  let icon: string;

  if (valid) {
    bg = 'bg-green-100';
    text = 'text-green-800';
    icon = '\u2713';
  } else if (isDsa || isUnsupported) {
    bg = 'bg-yellow-100';
    text = 'text-yellow-800';
    icon = '?';
  } else if (isMissing) {
    bg = 'bg-gray-100';
    text = 'text-gray-600';
    icon = '\u2014';
  } else {
    bg = 'bg-red-100';
    text = 'text-red-800';
    icon = '\u2717';
  }

  return (
    <div className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium ${bg} ${text}`}>
      <span className="font-bold">{icon}</span>
      <span>{label}</span>
      {algorithm && <span className="opacity-70">({algorithm})</span>}
      {error && !valid && (
        <span className="opacity-70 max-w-48 truncate" title={error}>
          — {error}
        </span>
      )}
    </div>
  );
}

export default function SignatureStatus({ result, loading }: Props) {
  if (loading || !result) {
    return (
      <div className="flex gap-2">
        <span className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-medium bg-gray-100 text-gray-500">
          {loading ? 'Verifying...' : 'No signatures'}
        </span>
      </div>
    );
  }

  return (
    <div className="flex flex-wrap gap-2">
      <Badge
        valid={result.level1.valid}
        label="Level 1"
        algorithm={result.level1.algorithm}
        error={result.level1.error}
      />
      <Badge
        valid={result.level2.valid}
        label="Level 2"
        algorithm={result.level2.algorithm}
        error={result.level2.error}
      />
    </div>
  );
}
