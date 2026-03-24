import esbuild from "esbuild";
import { cpSync, mkdirSync, readdirSync, rmSync, watch } from "node:fs";
import path from "node:path";

const watchMode = process.argv.includes("--watch");
const rootDir = process.cwd();
const outDir = path.join(rootDir, "dist");
const staticDir = path.join(rootDir, "static");

const buildOptions = {
  entryPoints: {
    "background/index": path.join(rootDir, "src/background/index.ts"),
    "content/index": path.join(rootDir, "src/content/index.ts"),
    "popup/index": path.join(rootDir, "src/popup/index.ts"),
    "sidepanel/index": path.join(rootDir, "src/sidepanel/index.ts"),
  },
  bundle: true,
  format: "iife",
  outdir: outDir,
  target: "chrome116",
  sourcemap: true,
  logLevel: "info",
};

function cleanDist() {
  rmSync(outDir, { recursive: true, force: true });
  mkdirSync(outDir, { recursive: true });
}

function copyStatic() {
  mkdirSync(outDir, { recursive: true });

  for (const entry of readdirSync(staticDir, { withFileTypes: true })) {
    const from = path.join(staticDir, entry.name);
    const to = path.join(outDir, entry.name);

    rmSync(to, { recursive: true, force: true });
    cpSync(from, to, { recursive: true });
  }
}

async function runBuild() {
  cleanDist();
  await esbuild.build(buildOptions);
  copyStatic();
  console.log("Built PromptProtect into dist/.");
}

async function runWatch() {
  cleanDist();
  copyStatic();

  const context = await esbuild.context(buildOptions);
  await context.watch();

  watch(staticDir, { recursive: true }, () => {
    copyStatic();
    console.log("Copied static assets.");
  });

  console.log("Watching PromptProtect...");
}

if (watchMode) {
  await runWatch();
} else {
  await runBuild();
}
