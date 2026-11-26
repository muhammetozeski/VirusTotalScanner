# Builds both single-exe profiles into .\publish\
#   small    : framework-dependent (~few MB; needs .NET 10 Desktop Runtime)
#   portable : self-contained      (~80-150 MB; runs on any Windows, no prerequisites)
$ErrorActionPreference = 'Stop'
$proj = Join-Path $PSScriptRoot 'VirusTotalScanner.csproj'
$root = Join-Path $PSScriptRoot 'publish'

$smallDir = Join-Path $root 'small'
$portableDir = Join-Path $root 'portable'

Write-Host '== Small (framework-dependent, single file) =='
dotnet publish $proj -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -o $smallDir --nologo
$smallSrc = Join-Path $smallDir 'VirusTotalScanner.exe'
$smallDst = Join-Path $smallDir 'VirusTotalScanner-FrameworkDependent-RequiresNET10.exe'
if (Test-Path $smallSrc) {
    Move-Item $smallSrc $smallDst -Force
}

Write-Host '== Portable (self-contained, single file, ReadyToRun) =='
dotnet publish $proj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:PublishReadyToRun=true -o $portableDir --nologo

Write-Host "`nDone. Output:"
Get-ChildItem $smallDir -Filter *.exe | ForEach-Object { "  small/$($_.Name)    {0:N1} MB" -f ($_.Length/1MB) }
Get-ChildItem $portableDir -Filter *.exe | ForEach-Object { "  portable/$($_.Name) {0:N1} MB" -f ($_.Length/1MB) }
