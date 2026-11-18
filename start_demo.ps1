# Opens the three demo windows: Interceptor, then Bob, then Alice.
# Mode: RSA-2048 + OAEP-SHA256.   Usage:  .\start_demo.ps1
param([int]$Port = 9001)

$root = $PSScriptRoot
$py = Join-Path $root '.venv\Scripts\python.exe'
$key = 'chat_keys_2048.json'

if (-not (Test-Path (Join-Path $root $key))) {
    & $py (Join-Path $root 'chat.py') setup --bits 2048 --key-file (Join-Path $root $key)
}
New-Item -ItemType Directory -Force (Join-Path $root 'captures') | Out-Null
$capture = 'captures\demo-{0}.jsonl' -f (Get-Date -Format 'yyyyMMdd-HHmmss')

function Open-Window($title, $command) {
    $script = "`$Host.UI.RawUI.WindowTitle = '$title'; Set-Location '$root'; $command"
    Start-Process powershell.exe -ArgumentList '-NoExit', '-NoProfile', '-Command', $script
}

Open-Window 'Interceptor (RSA-2048)' "& '$py' intercept.py --live --interface '\Device\NPF_Loopback' --port $Port --capture '$capture'"
Start-Sleep -Seconds 6
Open-Window 'Bob (RSA-2048)' "& '$py' chat.py listen --host 127.0.0.1 --port $Port --name Bob --key-file '$key'"
Start-Sleep -Seconds 2
Open-Window 'Alice (RSA-2048)' "& '$py' chat.py connect --host 127.0.0.1 --port $Port --name Alice"
