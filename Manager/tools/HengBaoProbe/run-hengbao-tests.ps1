<#
.SYNOPSIS
    恒宝（HengBao）CMBC U 宝 / PKCS#11 功能测试脚本。

.DESCRIPTION
    按固定顺序执行测试，并自动跟踪口令状态（改密/重置后后续步骤会用新口令）：

      0) 输出 DLL 内部日志目录准备情况（C:\HBLogFile / c:\hblogfile / c:\zj_log）
      1) 设备接口扫描      (--scan)                        只读，判断令牌通道是否存在
      2) 只读体检          (--list --sign)                 枚举/槽位/Token/对象/证书/签名
      3) 修改密码          (--changepin <新口令>)          写入：旧口令 → 新口令
      4) 初始化(清空+改密) (--reset <新口令>)              写入：删除全部对象 + 重设口令
      5) 导入证书          (--import-pfx <pfx>)            写入：证书对象 + 尝试私钥对象

    默认【只跑只读项】；写入类操作必须显式加 -RunWrites。
    每个写入步骤执行前会打印完整命令并要求输入 YES 确认（加 -Yes 可跳过确认）。

.PARAMETER Dll
    CMBCp.dll 路径（默认取 Library\HengBao USB Manage\CMBCp.dll）。

.PARAMETER Pin
    当前用户口令（出厂默认 111111，6-15 位）。

.PARAMETER NewPin
    改密/初始化时设置的新口令。

.PARAMETER Pfx
    待导入的 PKCS#12 文件路径。

.PARAMETER PfxPwd
    PFX 口令（不传则交互式输入）。

.PARAMETER RunWrites
    允许执行写入类步骤（改密 / 初始化 / 导入）。

.PARAMETER Yes
    写入步骤不再交互确认（谨慎使用）。

.PARAMETER CertOnly
    导入时只写证书对象，不尝试导入私钥。

.PARAMETER DryRun
    只打印将要执行的命令，不实际执行。

.EXAMPLE
    .\run-hengbao-tests.ps1
    只做只读体检（扫描 + 枚举 + 证书 + 签名自检）。

.EXAMPLE
    .\run-hengbao-tests.ps1 -RunWrites -PfxPwd 'YourPfxPassword' -Yes
    依次执行：体检 → 改密(111111→654321) → 初始化(清空+口令654321) → 导入 PFX。

.EXAMPLE
    .\run-hengbao-tests.ps1 -RunWrites -Pin 654321 -NewPin 111111 -Yes
    口令恢复为出厂默认。
#>
[CmdletBinding()]
param(
    [string]$Dll = 'G:\Codes\USBKeyDriver\Library\HengBao USB Manage\CMBCp.dll',
    [string]$Pin = '111111',
    [string]$NewPin = '654321',
    [string]$Pfx = 'G:\1.1.2-Pikachu_Common_Code_Sign_SHA256_V02.pfx',
    [string]$PfxPwd = '',
    [switch]$RunWrites,
    [switch]$Yes,
    [switch]$CertOnly,
    [switch]$DryRun
)

$ErrorActionPreference = 'Continue'
$script:Results = New-Object System.Collections.ArrayList
$script:CurrentPin = $Pin

function Write-Head([string]$t) {
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
    Write-Host "  $t" -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
}

function Resolve-Probe {
    $p = Join-Path $PSScriptRoot 'bin\Debug\net8.0\HengBaoProbe.exe'
    if (-not (Test-Path $p)) {
        $p = Join-Path $PSScriptRoot 'bin\Release\net8.0\HengBaoProbe.exe'
    }
    if (-not (Test-Path $p)) {
        Write-Host '[*] 未找到探针，正在编译 …' -ForegroundColor Yellow
        Push-Location $PSScriptRoot
        try { dotnet build -c Debug -v q --nologo | Out-Host } finally { Pop-Location }
        $p = Join-Path $PSScriptRoot 'bin\Debug\net8.0\HengBaoProbe.exe'
    }
    if (-not (Test-Path $p)) { throw "找不到 HengBaoProbe.exe（$p）" }
    return $p
}

function Prepare-LogDirs {
    # CMBCp.dll 的内部 trace 只有在这些目录存在时才会落盘（否则静默丢弃）
    foreach ($d in 'C:\HBLogFile', 'c:\hblogfile', 'c:\zj_log') {
        if (-not (Test-Path $d)) {
            try { New-Item -ItemType Directory -Force -Path $d | Out-Null; Write-Host "    已创建 $d" -ForegroundColor DarkGray }
            catch { Write-Host "    [!] 无法创建 $d：$($_.Exception.Message)" -ForegroundColor DarkYellow }
        }
    }
    $logs = @('C:\HBLogFile\TSPLogFile.txt', 'c:\zj_log\zj_csp.log')
    foreach ($f in $logs) {
        if (Test-Path $f) { Remove-Item $f -Force -ErrorAction SilentlyContinue }
    }
    Write-Host "    日志目录就绪；测试后可查看：$($logs -join ' , ')" -ForegroundColor DarkGray
}

function Confirm-Step([string]$title, [string]$cmdLine) {
    Write-Host ''
    Write-Host ">>> $title" -ForegroundColor Yellow
    Write-Host "    命令: $cmdLine" -ForegroundColor DarkGray
    if ($DryRun) { Write-Host '    [DryRun] 跳过执行' -ForegroundColor DarkYellow; return $false }
    if ($Yes) { return $true }
    $a = Read-Host '    输入 YES 继续（其它任意键跳过）'
    return ($a -eq 'YES')
}

function Invoke-Probe([string]$title, [string[]]$ProbeArgs) {
    $exe = Resolve-Probe
    $cmdLine = 'HengBaoProbe.exe ' + ($ProbeArgs -join ' ')
    Write-Host ''
    Write-Host "--- $title ---" -ForegroundColor Green
    Write-Host "    $cmdLine" -ForegroundColor DarkGray
    if ($DryRun) { [void]$script:Results.Add([pscustomobject]@{ Step = $title; Result = 'DryRun'; Detail = '' }); return 0 }
    & $exe @ProbeArgs 2>&1 | ForEach-Object { Write-Host ('    ' + $_) }
    $code = $LASTEXITCODE
    $verdict = if ($code -eq 0) { '完成(见输出)' } else { "退出码 $code" }
    [void]$script:Results.Add([pscustomobject]@{ Step = $title; Result = $verdict; Detail = $cmdLine })
    return $code
}

Write-Host ''
Write-Host '恒宝 CMBC U 宝 功能测试' -ForegroundColor Cyan
Write-Host "  DLL     : $Dll"
Write-Host "  当前口令: $Pin"
Write-Host "  新口令  : $NewPin"
Write-Host "  PFX     : $Pfx"
Write-Host "  写入模式: $($RunWrites.IsPresent)   自动确认: $($Yes.IsPresent)   DryRun: $($DryRun.IsPresent)"

if (-not (Test-Path $Dll)) { Write-Host "[!] 找不到 DLL：$Dll" -ForegroundColor Red; exit 2 }
if (-not (Test-Path $Pfx)) {
    Write-Host "[!] 提示：找不到 PFX 文件 $Pfx（PFX 自检与导入步骤会跳过/报错，其它步骤不受影响）" -ForegroundColor Yellow
}

# PFX 口令：写入模式且未传参时交互式询问（仅用于本地自检与后续导入）
$PfxPassword = $PfxPwd
if ([string]::IsNullOrEmpty($PfxPassword) -and $RunWrites -and -not $DryRun -and (Test-Path $Pfx)) {
    $sec = Read-Host '请输入 PFX 口令（用于本地自检与导入，输入内容不回显）' -AsSecureString
    $PfxPassword = [System.Net.NetworkCredential]::new('', $sec).Password
}

# ---------- 0) 准备 ----------
Write-Head '0) 准备：DLL 内部日志目录'
Prepare-LogDirs

# ---------- 0.5) PFX 本地自检 ----------
if (Test-Path $Pfx) {
    Write-Head '0.5) PFX 本地自检（不访问设备，先确认口令与内容）'
    $pfxArgs = @('--pfx-info', $Pfx)
    if (-not [string]::IsNullOrEmpty($PfxPassword)) { $pfxArgs += @('--pfx-pwd', $PfxPassword) }
    Invoke-Probe 'PFX 本地自检' $pfxArgs | Out-Null
}

# ---------- 1) 设备扫描 ----------
Write-Head '1) 设备接口扫描（只读）'
Invoke-Probe '设备接口扫描' @('--scan') | Out-Null

# ---------- 2) 只读体检 ----------
Write-Head '2) 只读体检（枚举 / Token 信息 / 对象统计 / 证书 / 签名自检）'
Invoke-Probe '只读体检' @($Dll, $script:CurrentPin, '--list', '--sign') | Out-Null

if (-not $RunWrites) {
    Write-Host ''
    Write-Host '[*] 当前为只读模式；如需执行「修改密码 / 初始化 / 导入证书」，请加 -RunWrites' -ForegroundColor Yellow
    Write-Host '    例： .\run-hengbao-tests.ps1 -RunWrites -PfxPwd ''<PFX口令>''' -ForegroundColor DarkGray
}

# ---------- 3) 修改密码 ----------
if ($RunWrites) {
    Write-Head '3) 修改密码（旧口令 → 新口令）'
    if ($script:CurrentPin -eq $NewPin) {
        Write-Host '    [跳过] 新旧口令相同' -ForegroundColor DarkYellow
    }
    else {
        $cmd = "HengBaoProbe.exe `"$Dll`" $($script:CurrentPin) --changepin $NewPin"
        $okPin = Confirm-Step '修改 U 宝口令' $cmd
        if (-not $okPin -and -not $DryRun) {
            Write-Host '    [跳过]' -ForegroundColor DarkYellow
        }
        else {
            if ($okPin) {
                Invoke-Probe '修改密码' @($Dll, $script:CurrentPin, '--changepin', $NewPin) | Out-Null
            }
            $script:CurrentPin = $NewPin
            Write-Host "    [*] 若上面显示 C_SetPIN 成功，后续步骤将使用新口令 $NewPin" -ForegroundColor DarkGray
            # 用新口令复核一次登录
            Write-Host ''
            Write-Host '    用新口令复核登录：' -ForegroundColor DarkGray
            Invoke-Probe '新口令复核（只读）' @($Dll, $script:CurrentPin, '--list') | Out-Null
        }
    }

    # ---------- 4) 初始化（清空内容 + 重设口令） ----------
    Write-Head '4) 初始化：清空内容 + 重设口令（--reset）'
    Write-Host '    注意：该操作会删除 U 宝上全部 PKCS#11 对象（证书/私钥/公钥/数据），不可撤销。' -ForegroundColor Yellow
    Write-Host "    注意：恒宝 U 宝不支持 PKCS#11 令牌初始化（C_InitToken 为 0x54 桩函数），" -ForegroundColor Yellow
    Write-Host "          此处的「初始化」= 清空对象 + C_SetPIN 改口令，等价实现银行场景的「重置 U 宝」。" -ForegroundColor Yellow
    $resetArgs = @($Dll, $script:CurrentPin, '--reset', $NewPin)
    if ($Yes) { $resetArgs += '--yes' }   # 探针内部仍有二次确认，-Yes 时一并跳过
    $cmd = 'HengBaoProbe.exe ' + (($resetArgs | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' ')
    $okReset = Confirm-Step '初始化 U 宝（清空 + 重设口令）' $cmd
    if (-not $okReset -and -not $DryRun) {
        Write-Host '    [跳过]' -ForegroundColor DarkYellow
    }
    else {
        if ($okReset) { Invoke-Probe '初始化（清空+重设口令）' $resetArgs | Out-Null }
        $script:CurrentPin = $NewPin   # 成功后新口令生效
    }

    # ---------- 5) 导入证书 ----------
    Write-Head '5) 导入证书（C_CreateObject）'
    $impArgs = @($Dll, $script:CurrentPin, '--import-pfx', $Pfx)
    if (-not [string]::IsNullOrEmpty($PfxPassword)) { $impArgs += @('--pfx-pwd', $PfxPassword) }
    if ($CertOnly) { $impArgs += '--cert-only' }
    if ($Yes) { $impArgs += '--yes' }
    $cmd = 'HengBaoProbe.exe ' + (($impArgs | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' ')
    if (Confirm-Step '导入 PFX 到 U 宝' $cmd) {
        Invoke-Probe '导入证书' $impArgs | Out-Null
        Invoke-Probe '导入后复核证书列表（只读）' @($Dll, $script:CurrentPin, '--list') | Out-Null
    }
    else { Write-Host '    [跳过]' -ForegroundColor DarkYellow }
}

# ---------- 汇总 ----------
Write-Head '测试汇总'
$script:Results | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
Write-Host '提示：' -ForegroundColor Cyan
Write-Host '  · 若各步骤都卡在 "C_GetTokenInfo → CKR_FUNCTION_FAILED(6)"，说明 U 宝令牌通道未就绪，' -ForegroundColor DarkGray
Write-Host '    详见 Roadmap/07-HengBao-U宝逆向分析.md §2.1（设备层日志显示卡片对 SELECT ADF1 回 6E00）。' -ForegroundColor DarkGray
Write-Host '  · DLL 内部日志：C:\HBLogFile\TSPLogFile.txt（设备层） / c:\zj_log\zj_csp.log（PKCS#11 层）' -ForegroundColor DarkGray
Write-Host '  · 证书「导入」在本设备上大概率只会成功写入证书对象；私钥必须由卡内生成（见 [B1]/[B2] 返回码）。' -ForegroundColor DarkGray
