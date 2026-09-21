# 手动创建ePass3003注册表桥接
# 简化版本，直接执行桥接操作

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "ePass3003 注册表桥接 - 自动执行" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# 检查管理员权限
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "错误: 需要管理员权限" -ForegroundColor Red
    Write-Host "请以管理员身份运行PowerShell，然后执行此脚本" -ForegroundColor Yellow
    exit 1
}

Write-Host "[1] 检查HZCA配置..." -ForegroundColor Yellow

$sourceWow = "HKLM:\SOFTWARE\WOW6432Node\EnterSafe\ePass3003_HCCB"
$targetWow = "HKLM:\SOFTWARE\WOW6432Node\EnterSafe\ePass3003"

$cspSourceWow = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Defaults\Provider\EnterSafe ePass3003 CSP For HCCB V1.0"
$cspTargetWow = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Defaults\Provider\EnterSafe ePass3003 CSP"

if (-not (Test-Path $sourceWow)) {
    Write-Host "错误: 未找到HZCA配置" -ForegroundColor Red
    exit 1
}

Write-Host "找到HZCA配置: $sourceWow" -ForegroundColor Green
Write-Host ""

Write-Host "[2] 创建注册表桥接..." -ForegroundColor Yellow

# 创建官方注册表路径
if (-not (Test-Path $targetWow)) {
    New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\EnterSafe" -Name "ePass3003" -Force | Out-Null
    Write-Host "  创建: $targetWow" -ForegroundColor Green
}

# 复制所有值
$source = Get-ItemProperty $sourceWow
$copied = 0
$source.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
    Set-ItemProperty -Path $targetWow -Name $_.Name -Value $_.Value
    Write-Host "  $($_.Name) = $($_.Value)" -ForegroundColor Gray
    $copied++
}

Write-Host "  复制了 $copied 个配置项" -ForegroundColor Green
Write-Host ""

Write-Host "[3] 创建CSP别名..." -ForegroundColor Yellow

if (Test-Path $cspSourceWow) {
    # 创建CSP路径
    if (-not (Test-Path $cspTargetWow)) {
        $parent = Split-Path $cspTargetWow -Parent
        New-Item -Path $parent -Name "EnterSafe ePass3003 CSP" -Force | Out-Null
        Write-Host "  创建: $cspTargetWow" -ForegroundColor Green
    }
    
    # 复制CSP配置
    $cspSource = Get-ItemProperty $cspSourceWow
    $cspSource.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
        Set-ItemProperty -Path $cspTargetWow -Name $_.Name -Value $_.Value
        Write-Host "  $($_.Name) = $($_.Value)" -ForegroundColor Gray
    }
    
    Write-Host "  CSP别名创建成功" -ForegroundColor Green
}
else {
    Write-Host "  警告: 未找到HZCA CSP配置" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=========================================" -ForegroundColor Green
Write-Host "桥接创建完成！" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green
Write-Host ""

# 验证
Write-Host "[验证] 检查桥接结果..." -ForegroundColor Yellow
Write-Host ""

Write-Host "官方注册表路径:" -ForegroundColor Cyan
if (Test-Path $targetWow) {
    Get-ItemProperty $targetWow | Select-Object Path, Version | Format-List
}

Write-Host "官方CSP:" -ForegroundColor Cyan
if (Test-Path $cspTargetWow) {
    Get-ItemProperty $cspTargetWow | Select-Object Image, Type | Format-List
}

Write-Host ""
Write-Host "现在可以测试官方工具了！" -ForegroundColor Green
Write-Host "运行: ePassManager_3003.exe" -ForegroundColor Yellow
