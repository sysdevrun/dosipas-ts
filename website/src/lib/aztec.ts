import * as bwipjs from 'bwip-js/browser';

export function renderAztec(
  canvas: HTMLCanvasElement,
  data: Uint8Array,
  scale: number = 3,
): void {
  // Convert binary data to ^NNN caret notation for bwip-js
  const text = Array.from(data)
    .map((b) => `^${b.toString().padStart(3, '0')}`)
    .join('');

  bwipjs.toCanvas(canvas, {
    bcid: 'azteccode',
    text,
    parse: true,
    scale,
    eclevel: 23,
  } as bwipjs.RenderOptions);
}

export function aztecToDataUrl(data: Uint8Array, scale: number = 4): string {
  const canvas = document.createElement('canvas');
  renderAztec(canvas, data, scale);
  return canvas.toDataURL('image/png');
}
