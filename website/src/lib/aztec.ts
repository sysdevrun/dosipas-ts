import * as bwipjs from 'bwip-js/browser';

export function renderAztec(
  canvas: HTMLCanvasElement,
  data: Uint8Array,
  scale: number = 3,
): void {
  // bwip-js expects hex string for binary data
  const hex = Array.from(data)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  // The 'encoding' option is supported at runtime but not in the type defs
  bwipjs.toCanvas(canvas, {
    bcid: 'azteccode',
    text: hex,
    encoding: 'hexadecimal',
    scale,
    eclevel: 23,
  } as bwipjs.RenderOptions);
}

export function aztecToDataUrl(data: Uint8Array, scale: number = 4): string {
  const canvas = document.createElement('canvas');
  renderAztec(canvas, data, scale);
  return canvas.toDataURL('image/png');
}
