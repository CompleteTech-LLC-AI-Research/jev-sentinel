# No downloads. Requires Python 3.10+ available as python.
$ErrorActionPreference = 'Stop'
& python -I (Join-Path $PSScriptRoot 'install.py') @args
exit $LASTEXITCODE
