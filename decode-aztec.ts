import { decodeTicket, SAMPLE_TICKET_HEX } from './src/index';

// Use hex from CLI argument, or fall back to sample fixture
const hex = process.argv[2] || SAMPLE_TICKET_HEX;

try {
  const ticket = decodeTicket(hex);
  console.log(JSON.stringify(ticket, (_, v) => {
    if (v instanceof Uint8Array) return `<${v.length} bytes: ${Array.from(v.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join('')}${v.length > 16 ? '...' : ''}>`;
    return v;
  }, 2));
} catch (e) {
  console.error('Decode failed:', e);
}
