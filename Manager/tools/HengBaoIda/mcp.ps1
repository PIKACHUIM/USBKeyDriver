# 驱动 x64dbg 的 MCP 桥接（SSE 传输：/sse 收，/message 发）
#
#   .\mcp.ps1 list                                  列出 x32dbg 暴露的 MCP 工具
#   .\mcp.ps1 call <tool> <params.json> [waitSec]   调用一个工具，params.json 为参数对象
#
# 说明：经典 SSE 传输下 POST 只返回 202，真正的 JSON-RPC 应答从 /sse 流里回来，
# 所以这里把 SSE 流重定向到临时文件，发完再读回来。
param(
    [Parameter(Mandatory = $true, Position = 0)][string]$Mode,
    [Parameter(Position = 1)][string]$ToolName,
    [Parameter(Position = 2)][string]$ParamsFile,
    [Parameter(Position = 3)][int]$WaitSec = 8
)

$ErrorActionPreference = 'SilentlyContinue'
$url = 'http://127.0.0.1:3000'
$log = Join-Path $env:TEMP 'mcp_sse.log'
Remove-Item $log -Force

function Invoke-McpRaw([string[]]$Bodies, [int]$Wait) {
    $proc = Start-Process -FilePath 'curl.exe' -ArgumentList @('-s', '-N', '-m', "$($Wait + 10)", "$url/sse") `
        -RedirectStandardOutput $log -NoNewWindow -PassThru
    Start-Sleep -Milliseconds 900
    foreach ($b in $Bodies) {
        if ([string]::IsNullOrWhiteSpace($b)) { continue }
        curl.exe -s -m 6 -X POST -H 'Content-Type: application/json' --data-binary $b "$url/message" | Out-Null
        Start-Sleep -Milliseconds 400
    }
    Start-Sleep -Seconds $Wait
    Stop-Process -Id $proc.Id -Force
    Get-Content $log -Raw
}

$init = '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"hengbao-re","version":"1.0"}}}'
$inited = '{"jsonrpc":"2.0","method":"notifications/initialized"}'

if ($Mode -eq 'list') {
    $out = Invoke-McpRaw @($init, $inited, '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}') $WaitSec
    Write-Output $out
}
elseif ($Mode -eq 'call') {
    if (-not $ToolName) { Write-Output 'need tool name'; exit 1 }
    $params = '{}'
    if ($ParamsFile -and (Test-Path $ParamsFile)) { $params = (Get-Content $ParamsFile -Raw).Trim() }
    $body = '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"' + $ToolName + '","arguments":' + $params + '}}'
    $out = Invoke-McpRaw @($init, $inited, $body) $WaitSec
    Write-Output $out
}
else {
    Write-Output 'usage: mcp.ps1 list | mcp.ps1 call <tool> <params.json> [waitSec]'
}
