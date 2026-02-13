import { readBarcodesFromImageData, type ReaderOptions } from 'zxing-wasm/reader';

const READER_OPTIONS: ReaderOptions = {
  formats: ['Aztec'],
  tryHarder: true,
  maxNumberOfSymbols: 1,
};

export async function scanFromImageFile(file: File): Promise<Uint8Array | null> {
  const bitmap = await createImageBitmap(file);
  const canvas = new OffscreenCanvas(bitmap.width, bitmap.height);
  const ctx = canvas.getContext('2d')!;
  ctx.drawImage(bitmap, 0, 0);
  const imageData = ctx.getImageData(0, 0, bitmap.width, bitmap.height);
  bitmap.close();

  const results = await readBarcodesFromImageData(imageData, READER_OPTIONS);
  if (results.length === 0) return null;
  return results[0].bytes;
}

export async function scanFromVideoFrame(
  video: HTMLVideoElement,
): Promise<Uint8Array | null> {
  const canvas = new OffscreenCanvas(video.videoWidth, video.videoHeight);
  const ctx = canvas.getContext('2d')!;
  ctx.drawImage(video, 0, 0);
  const imageData = ctx.getImageData(0, 0, video.videoWidth, video.videoHeight);

  const results = await readBarcodesFromImageData(imageData, READER_OPTIONS);
  if (results.length === 0) return null;
  return results[0].bytes;
}
