<#
.SYNOPSIS
    LNCA/华大 UKey 传输密钥（P1=0 通道）候选验证脚本。

.DESCRIPTION
    背景（详见 Roadmap/05-LNCA逆向分析案例.md §12.9）：
      - 设备用户 PIN 与管理员认证通道在本卡上均已锁定（0x6983）；
      - 唯一未锁定的通道是「外部认证 P1=0」，其密钥来自 SDK 内置密钥表；
      - HDCOS_LNCA.dll 内部可自算挑战应答（sub_8D10 变换 + sub_8DC0 计算），
        因此可在不上锁的前提下验证任意候选密钥（每个候选约 150 ms）。

    本脚本把候选清单分批喂给 LncaProbe 的 --key 模式，命中即报出。

.PARAMETER CandidatesFile
    候选清单文本文件，每行一个候选（UTF-8，支持 # 注释，hex: 前缀表示原始字节）。

.PARAMETER Key
    直接以命令行追加候选（可多个）。

.PARAMETER Port
    设备端口索引，默认 0。

.EXAMPLE
    .\lnca_keytest.ps1
    .\lnca_keytest.ps1 -CandidatesFile .\keys.txt
    .\lnca_keytest.ps1 -Key "87654321" "hex:0011223344556677"
#>
[CmdletBinding()]
param(
    [string]$CandidatesFile = "",
    [string[]]$Key = @(),
    [int]$Port = 0
)

$ErrorActionPreference = "Stop"

# ---- 定位探针可执行文件（本归档内 _逆向分析/probe/LncaProbe） ----
$revRoot = Split-Path -Parent $PSScriptRoot           # ...\_逆向分析
$proj = Join-Path $revRoot "probe\LncaProbe"
$probe = Join-Path $proj "bin\Release\net8.0\LncaProbe.exe"
if (-not (Test-Path $probe)) { $probe = Join-Path $proj "bin\Debug\net8.0\LncaProbe.exe" }
if (-not (Test-Path $probe)) {
    Write-Host "未找到 LncaProbe.exe，正在编译..." -ForegroundColor Yellow
    & dotnet build (Join-Path $proj "LncaProbe.csproj") -c Release --nologo | Out-Null
    $probe = Join-Path $proj "bin\Release\net8.0\LncaProbe.exe"
}
if (-not (Test-Path $probe)) {
    Write-Host "编译失败，请手动执行：" -ForegroundColor Yellow
    Write-Host "  dotnet build `"$proj\LncaProbe.csproj`" -c Release"
    exit 1
}

# ---- 组装候选清单 ----
$builtin = @(
    # DLL 内置密钥表（条目1 = id 0x11，条目2 = id 0x22）
    "hex:A62F1A1D6F5F85E2F31DFA933F273947"
    "hex:637974627968797873796B7968620831"
    "cytbyhyxsykyhb"
    "cytbyhyx"

    # 常见出厂/部署口令（8 位及 16 位）
    "12345678", "1234567890", "11111111", "00000000", "88888888", "66666666"
    "01234567", "87654321", "12341234", "1qaz2wsx", "qwertyui", "abcd1234"
    "LNCA1234", "lnca1234", "LNCACSPS", "HDSC1234", "huada123", "HUADA123"
    "CIDCUSB1", "cidcusb1", "Cidcex01", "GP_ADM01"

    # 设备标识派生
    "SZD23B10", "01102001519176", "01519176", "0519176", "01102001"
    "hex:0000000000000000", "hex:FFFFFFFFFFFFFFFF"
    "hex:00000000000000000000000000000000"
    "hex:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
)

$list = @()
if ($CandidatesFile) {
    if (-not (Test-Path $CandidatesFile)) { Write-Host "候选文件不存在：$CandidatesFile" -ForegroundColor Red; exit 1 }
    $list += Get-Content -LiteralPath $CandidatesFile -Encoding UTF8 |
             Where-Object { $_ -and -not $_.TrimStart().StartsWith("#") } |
             ForEach-Object { $_.Trim() }
}
$list += $Key
if ($list.Count -eq 0) { $list = $builtin }
$list = $list | Where-Object { $_ } | Select-Object -Unique

Write-Host "=== LNCA 传输密钥候选验证 ===" -ForegroundColor Cyan
Write-Host "探针：$probe"
Write-Host "候选数：$($list.Count)（每个候选试 [原样] 与 [经 sub_8D10 变换] 两种形态）"
Write-Host ""

# ---- 分批执行（每批 20 个，避免命令行过长）----
$batchSize = 20
$hit = $null
for ($i = 0; $i -lt $list.Count; $i += $batchSize) {
    $batch = $list[$i..([Math]::Min($i + $batchSize - 1, $list.Count - 1))]
    Write-Host "--- 批次 $([Math]::Floor($i / $batchSize) + 1)/$([Math]::Ceiling($list.Count / $batchSize)) ---" -ForegroundColor DarkGray
    $out = & $probe --key @batch --port $Port 2>&1
    $out | ForEach-Object { Write-Host "  $_" }
    $match = $out | Select-String -Pattern "密钥正确"
    if ($match) {
        $hit = ($match -join "`n")
        break
    }
}

Write-Host ""
if ($hit) {
    Write-Host "*** 命中！***" -ForegroundColor Green
    Write-Host $hit
    Write-Host ""
    Write-Host "下一步：用命中密钥执行完全格式化（会清除证书与数据区）："
    Write-Host "  & `"$probe`" --format $Port <新PIN> <SO口令>"
    exit 0
} else {
    Write-Host "未命中（全部候选均被卡拒绝）。" -ForegroundColor Yellow
    Write-Host "说明：该卡传输密钥不在本次候选中；穷举 6~16 字节口令空间不可行，需向厂商/客户索取。"
    exit 2
}
