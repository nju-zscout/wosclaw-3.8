# PowerShell version of bundle-a2ui.sh for Windows
$ErrorActionPreference = 'Stop'

# function On-Error {
#     Write-Error "A2UI bundling failed. Re-run with: pnpm canvas:a2ui:bundle"
#     Write-Error "If this persists, verify pnpm deps and try again."
# }
# trap { On-Error; exit 1 }

$RootDir = Resolve-Path "$PSScriptRoot/.."
$HashFile = Join-Path $RootDir 'src/canvas-host/a2ui/.bundle.hash'
$OutputFile = Join-Path $RootDir 'src/canvas-host/a2ui/a2ui.bundle.js'
$RendererDir = Join-Path $RootDir 'vendor/a2ui/renderers/lit'
$AppDir = Join-Path $RootDir 'apps/shared/OpenClawKit/Tools/CanvasA2UI'

# Check for required directories
if (!(Test-Path $RendererDir) -or !(Test-Path $AppDir)) {
    if (Test-Path $OutputFile) {
        Write-Host "A2UI sources missing; keeping prebuilt bundle."
        exit 0
    }
    Write-Error "A2UI sources missing and no prebuilt bundle found at: $OutputFile"
    exit 1
}

$InputPaths = @()
$InputPaths += Join-Path $RootDir 'package.json'
$InputPaths += Join-Path $RootDir 'pnpm-lock.yaml'
$InputPaths += $RendererDir
$InputPaths += $AppDir

# Compute hash using Node.js
$NodeHashScript = @'
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";

const rootDir = process.env.ROOT_DIR ?? process.cwd();
const inputs = process.argv.slice(2);
const files = [];

async function walk(entryPath) {
  const st = await fs.stat(entryPath);
  if (st.isDirectory()) {
    const entries = await fs.readdir(entryPath);
    for (const entry of entries) {
      await walk(path.join(entryPath, entry));
    }
    return;
  }
  files.push(entryPath);
}

for (const input of inputs) {
  await walk(input);
}

function normalize(p) {
  return p.split(path.sep).join("/");
}

files.sort((a, b) => normalize(a).localeCompare(normalize(b)));

const hash = createHash("sha256");
for (const filePath of files) {
  const rel = normalize(path.relative(rootDir, filePath));
  hash.update(rel);
  hash.update("\0");
  hash.update(await fs.readFile(filePath));
  hash.update("\0");
}

process.stdout.write(hash.digest("hex"));
'@

$TempFile = Join-Path $env:TEMP "hash-script.mjs"
Set-Content -Path $TempFile -Value $NodeHashScript
$env:ROOT_DIR = $RootDir
$CurrentHash = node $TempFile $InputPaths
Remove-Item $TempFile

$PreviousHash = if (Test-Path $HashFile) { Get-Content $HashFile -Raw } else { '' }
if ($PreviousHash -eq $CurrentHash -and (Test-Path $OutputFile)) {
    Write-Host "A2UI bundle up to date; skipping."
    exit 0
}

pnpm exec tsc -p (Join-Path $RendererDir 'tsconfig.json')
if (Get-Command rolldown -ErrorAction SilentlyContinue) {
    rolldown -c (Join-Path $AppDir 'rolldown.config.mjs')
} else {
    pnpm dlx rolldown -c (Join-Path $AppDir 'rolldown.config.mjs')
}

Set-Content -Path $HashFile -Value $CurrentHash
