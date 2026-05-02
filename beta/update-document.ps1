param(
  [Parameter(Mandatory = $true)]
  [string]$InputDocx,

  [string]$ContentKey = $env:CONTENT_KEY
)

$ErrorActionPreference = "Stop"

if (-not $ContentKey) {
  $ContentKey = "KsuvxqjyDvvk6vNGdJmQSwANw4MzhgHL"
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoDir = Split-Path -Parent $scriptDir
$toolsDir = Join-Path $scriptDir "tools"
$backendDataDir = Join-Path $scriptDir "backend\data"
$inputPath = (Resolve-Path -LiteralPath $InputDocx).Path
$nodeCmd = Get-Command node -ErrorAction SilentlyContinue

if ($nodeCmd) {
  $node = $nodeCmd.Source
} else {
  $bundledNode = Join-Path $env:USERPROFILE ".cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe"
  if (-not (Test-Path -LiteralPath $bundledNode)) {
    throw "Node.js not found. Install Node.js or run this from Codex where the bundled runtime exists."
  }
  $node = $bundledNode
}

$env:CONTENT_KEY = $ContentKey

Write-Host "Using document: $inputPath"
Write-Host "Updating encrypted content..."

& $node (Join-Path $toolsDir "ingest.js") `
  --input $inputPath `
  --output (Join-Path $backendDataDir "chunks.json")

if ($LASTEXITCODE -ne 0) {
  throw "Document update failed."
}

$storedDoc = Join-Path $toolsDir "filegg.docx"
$storedDocPath = (Resolve-Path -LiteralPath $storedDoc -ErrorAction SilentlyContinue).Path
if ($storedDocPath -ne $inputPath) {
  Copy-Item -LiteralPath $inputPath -Destination $storedDoc -Force
}

Write-Host ""
Write-Host "Done."
Write-Host "Updated:"
Write-Host "  beta\backend\data\chunks.json"
Write-Host "  beta\backend\data\manifest.json"
Write-Host "  beta\tools\filegg.docx"
Write-Host ""
Write-Host "Next: commit/push these files and redeploy Railway."
