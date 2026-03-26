import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";

const ROOT = path.resolve(process.cwd());
const OUT_DIR = path.join(ROOT, "static", "icons");

function makeCrcTable() {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
}

const CRC_TABLE = makeCrcTable();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

function u32be(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
}

function chunk(type, data) {
  const typeBuf = Buffer.from(type, "ascii");
  const lenBuf = u32be(data.length);
  const crcBuf = u32be(crc32(Buffer.concat([typeBuf, data])));
  return Buffer.concat([lenBuf, typeBuf, data, crcBuf]);
}

function writePng({ width, height, rgba }) {
  if (rgba.length !== width * height * 4)
    throw new Error("Bad RGBA buffer length");

  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // color type RGBA
  ihdr[10] = 0; // compression
  ihdr[11] = 0; // filter
  ihdr[12] = 0; // interlace

  // Raw scanlines: each row prefixed with filter byte 0
  const stride = width * 4;
  const raw = Buffer.alloc(height * (1 + stride));
  for (let y = 0; y < height; y++) {
    raw[y * (1 + stride)] = 0;
    rgba.copy(raw, y * (1 + stride) + 1, y * stride, y * stride + stride);
  }

  const idatData = zlib.deflateSync(raw, { level: 9 });

  const png = Buffer.concat([
    signature,
    chunk("IHDR", ihdr),
    chunk("IDAT", idatData),
    chunk("IEND", Buffer.alloc(0)),
  ]);

  return png;
}

function pointInPolygon(x, y, pts) {
  // Ray casting
  let inside = false;
  for (let i = 0, j = pts.length - 1; i < pts.length; j = i++) {
    const xi = pts[i][0];
    const yi = pts[i][1];
    const xj = pts[j][0];
    const yj = pts[j][1];

    const intersect =
      yi > y !== yj > y && x < ((xj - xi) * (y - yi)) / (yj - yi + 1e-9) + xi;
    if (intersect) inside = !inside;
  }
  return inside;
}

function clamp01(v) {
  return Math.max(0, Math.min(1, v));
}

function mix(a, b, t) {
  return a + (b - a) * t;
}

function drawShieldRgba(size) {
  const width = size;
  const height = size;
  const rgba = Buffer.alloc(width * height * 4);

  // Shield polygon in normalized coordinates.
  const outerN = [
    [0.5, 0.08],
    [0.78, 0.18],
    [0.86, 0.32],
    [0.8, 0.62],
    [0.62, 0.84],
    [0.5, 0.93],
    [0.38, 0.84],
    [0.2, 0.62],
    [0.14, 0.32],
    [0.22, 0.18],
  ];

  const innerN = outerN.map(([x, y]) => [
    mix(0.5, x, 0.86),
    mix(0.52, y, 0.86),
  ]);

  const outer = outerN.map(([x, y]) => [x * (width - 1), y * (height - 1)]);
  const inner = innerN.map(([x, y]) => [x * (width - 1), y * (height - 1)]);

  const outerFill = { r: 16, g: 163, b: 127, a: 255 }; // #10a37f
  const innerFill = { r: 13, g: 138, b: 106, a: 255 }; // slightly darker
  const borderFill = { r: 7, g: 84, b: 66, a: 255 }; // dark border

  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const px = x + 0.5;
      const py = y + 0.5;

      const inOuter = pointInPolygon(px, py, outer);
      if (!inOuter) continue;

      const inInner = pointInPolygon(px, py, inner);

      let c = inInner ? innerFill : borderFill;

      // Subtle highlight towards top-left inside inner.
      if (inInner) {
        const nx = px / (width - 1);
        const ny = py / (height - 1);
        const hl = clamp01(1.0 - Math.hypot(nx - 0.28, ny - 0.2) / 0.55);
        const t = 0.18 * hl;
        c = {
          r: Math.round(mix(c.r, 255, t)),
          g: Math.round(mix(c.g, 255, t)),
          b: Math.round(mix(c.b, 255, t)),
          a: c.a,
        };
      }

      const idx = (y * width + x) * 4;
      rgba[idx] = c.r;
      rgba[idx + 1] = c.g;
      rgba[idx + 2] = c.b;
      rgba[idx + 3] = c.a;
    }
  }

  return { width, height, rgba };
}

function downsampleRgba({ width, height, rgba, scale }) {
  if (!Number.isInteger(scale) || scale <= 1) {
    return { width, height, rgba };
  }

  if (width % scale !== 0 || height % scale !== 0) {
    throw new Error("Downsample scale must divide width/height exactly");
  }

  const outWidth = Math.floor(width / scale);
  const outHeight = Math.floor(height / scale);
  const out = Buffer.alloc(outWidth * outHeight * 4);

  for (let y = 0; y < outHeight; y++) {
    for (let x = 0; x < outWidth; x++) {
      let r = 0;
      let g = 0;
      let b = 0;
      let a = 0;

      for (let sy = 0; sy < scale; sy++) {
        const srcY = y * scale + sy;
        for (let sx = 0; sx < scale; sx++) {
          const srcX = x * scale + sx;
          const idx = (srcY * width + srcX) * 4;
          r += rgba[idx];
          g += rgba[idx + 1];
          b += rgba[idx + 2];
          a += rgba[idx + 3];
        }
      }

      const denom = scale * scale;
      const outIdx = (y * outWidth + x) * 4;
      out[outIdx] = Math.round(r / denom);
      out[outIdx + 1] = Math.round(g / denom);
      out[outIdx + 2] = Math.round(b / denom);
      out[outIdx + 3] = Math.round(a / denom);
    }
  }

  return { width: outWidth, height: outHeight, rgba: out };
}

function renderShieldRgba(size) {
  const scale = size <= 19 ? 8 : size <= 48 ? 4 : size <= 128 ? 2 : 1;
  const hi = drawShieldRgba(size * scale);
  return downsampleRgba({ ...hi, scale });
}

function main() {
  fs.mkdirSync(OUT_DIR, { recursive: true });

  const sizes = [16, 19, 32, 38, 48, 128];
  for (const size of sizes) {
    const { width, height, rgba } = renderShieldRgba(size);
    const png = writePng({ width, height, rgba });
    const outPath = path.join(OUT_DIR, `shield-${size}.png`);
    fs.writeFileSync(outPath, png);
    // eslint-disable-next-line no-console
    console.log(`Wrote ${path.relative(ROOT, outPath)}`);
  }
}

main();
