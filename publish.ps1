# Builds both single-exe profiles into .\publish\
#   small    : framework-dependent (~few MB; needs .NET 10 Desktop Runtime)
#   portable : self-contained      (~80-150 MB; runs on any Windows, no prerequisites)
$ErrorActionPreference = 'Stop'
$proj = Join-Path $PSScriptRoot 'VirusTotalScanner.csproj'
$root = Join-Path $PSScriptRoot 'publish'

Write-Host '== Small (framework-dependent, single file) =='
dotnet publish $proj -c Release -r win-x64 --self-contained false -o (Join-Path $root 'small') --nologo

Write-Host '== Portable (self-contained, single file) =='
dotnet publish $proj -c Release -r win-x64 --self-contained true -o (Join-Path $root 'portable') --nologo

Write-Host "`nDone. Output:"
Get-ChildItem (Join-Path $root 'small') -Filter *.exe | ForEach-Object { "  small/$($_.Name)    {0:N1} MB" -f ($_.Length/1MB) }
Get-ChildItem (Join-Path $root 'portable') -Filter *.exe | ForEach-Object { "  portable/$($_.Name) {0:N1} MB" -f ($_.Length/1MB) }
