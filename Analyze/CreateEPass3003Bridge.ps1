# ePass3003 注册表桥接工具
# 目的：让官方ePass3003管理工具能够识别HZCA定制版设备
# 原理：在官方工具期望的注册表路径下创建软链接或镜像数据

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "ePass3003 注册表桥接工具" -ForegroundColor Cyan
Write-Host "让官方工具识别HZCA定制版设备" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# 检查管理员权限
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "错误: 需要管理员权限来修改注册表" -ForegroundColor Red
    Write-Host "请右键以管理员身份运行此脚本" -ForegroundColor Yellow
    exit 1
}

Write-Host "[1] 检查现有配置..." -ForegroundColor Yellow
Write-Host ""

# 源路径（HZCA）
$sourcePathMain = "HKLM:\SOFTWARE\EnterSafe\ePass3003_HCCB"
$sourcePathWow = "HKLM:\SOFTWARE\WOW6432Node\EnterSafe\ePass3003_HCCB"

# 目标路径（官方工具期望的路径）
$targetPathMain = "HKLM:\SOFTWARE\EnterSafe\ePass3003"
$targetPathWow = "HKLM:\SOFTWARE\WOW6432Node\EnterSafe\ePass3003"

# CSP源路径和目标路径
$cspSourcePath = "HKLM:\SOFTWARE\Microsoft\Cryptography\Defaults\Provider\EnterSafe ePass3003 CSP For HCCB V1.0"
$cspSourcePathWow = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Defaults\Provider\EnterSafe ePass3003 CSP For HCCB V1.0"
$cspTargetPath = "HKLM:\SOFTWARE\Microsoft\Cryptography\Defaults\Provider\EnterSafe ePass3003 CSP"
$cspTargetPathWow = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Defaults\Provider\EnterSafe ePass3003 CSP"

# 检查HZCA配置是否存在
Write-Host "检查HZCA配置:" -ForegroundColor Cyan
$hzcaExists = $false
foreach ($path in @($sourcePathMain, $sourcePathWow)) {
    if (Test-Path $path) {
        Write-Host "  [找到] $path" -ForegroundColor Green
        $hzcaExists = $true
        
        # 显示配置内容
        $config = Get-ItemProperty $path
        $config.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
            Write-Host "    $($_.Name) = $($_.Value)" -ForegroundColor Gray
        }
    }
    else {
        Write-Host "  [未找到] $path" -ForegroundColor DarkGray
    }
}

if (-not $hzcaExists) {
    Write-Host ""
    Write-Host "错误: 未找到HZCA配置，请确保HZCA工具已安装" -ForegroundColor Red
    exit 1
}

Write-Host ""

# 检查官方配置是否已存在
Write-Host "检查官方配置:" -ForegroundColor Cyan
$officialExists = $false
foreach ($path in @($targetPathMain, $targetPathWow)) {
    if (Test-Path $path) {
        Write-Host "  [已存在] $path" -ForegroundColor Yellow
        $officialExists = $true
    }
    else {
        Write-Host "  [不存在] $path" -ForegroundColor DarkGray
    }
}

Write-Host ""

# 询问操作模式
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "选择操作模式:" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "1. 创建桥接 - 复制HZCA配置到官方路径（推荐）" -ForegroundColor Green
Write-Host "2. 创建CSP别名 - 注册通用CSP名称指向HZCA" -ForegroundColor Green
Write-Host "3. 完整桥接 - 同时创建注册表和CSP桥接" -ForegroundColor Green
Write-Host "4. 移除桥接 - 删除所有桥接配置" -ForegroundColor Yellow
Write-Host "5. 退出" -ForegroundColor Gray
Write-Host ""
Write-Host -NoNewline "请选择 (1-5): "
$choice = Read-Host

switch ($choice) {
    "1" {
        Write-Host ""
        Write-Host "[2] 创建注册表桥接..." -ForegroundColor Yellow
        Write-Host ""
        
        # 复制注册表配置
        if (Test-Path $sourcePathWow) {
            Write-Host "从 WOW6432Node 路径复制配置..." -ForegroundColor Cyan
            
            # 创建目标路径
            if (-not (Test-Path $targetPathWow)) {
                New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\EnterSafe" -Name "ePass3003" -Force | Out-Null
                Write-Host "  创建: $targetPathWow" -ForegroundColor Green
            }
            
            # 复制所有值
            $source = Get-ItemProperty $sourcePathWow
            $source.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
                Set-ItemProperty -Path $targetPathWow -Name $_.Name -Value $_.Value
                Write-Host "  复制: $($_.Name) = $($_.Value)" -ForegroundColor Gray
            }
            
            Write-Host "  ✓ WOW6432Node 配置复制完成" -ForegroundColor Green
        }
        
        if (Test-Path $sourcePathMain) {
            Write-Host "从主路径复制配置..." -ForegroundColor Cyan
            
            # 创建目标路径
            if (-not (Test-Path $targetPathMain)) {
                New-Item -Path "HKLM:\SOFTWARE\EnterSafe" -Name "ePass3003" -Force | Out-Null
                Write-Host "  创建: $targetPathMain" -ForegroundColor Green
            }
            
            # 复制所有值
            $source = Get-ItemProperty $sourcePathMain
            $source.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
                Set-ItemProperty -Path $targetPathMain -Name $_.Name -Value $_.Value
                Write-Host "  复制: $($_.Name) = $($_.Value)" -ForegroundColor Gray
            }
            
            Write-Host "  ✓ 主路径配置复制完成" -ForegroundColor Green
        }
        
        Write-Host ""
        Write-Host "✓ 注册表桥接创建成功！" -ForegroundColor Green
        Write-Host ""
        Write-Host "注意: 此方法只复制了配置路径，CSP名称仍然不同。" -ForegroundColor Yellow
        Write-Host "官方工具可能仍然无法完全识别设备。" -ForegroundColor Yellow
        Write-Host "建议使用选项3（完整桥接）。" -ForegroundColor Yellow
    }
    
    "2" {
        Write-Host ""
        Write-Host "[2] 创建CSP别名..." -ForegroundColor Yellow
        Write-Host ""
        
        # 复制CSP注册
        if (Test-Path $cspSourcePathWow) {
            Write-Host "从 WOW6432Node 复制CSP配置..." -ForegroundColor Cyan
            
            # 创建目标CSP路径
            if (-not (Test-Path $cspTargetPathWow)) {
                $parentPath = Split-Path $cspTargetPathWow -Parent
                if (-not (Test-Path $parentPath)) {
                    New-Item -Path $parentPath -Force | Out-Null
                }
                New-Item -Path $parentPath -Name "EnterSafe ePass3003 CSP" -Force | Out-Null
                Write-Host "  创建: $cspTargetPathWow" -ForegroundColor Green
            }
            
            # 复制CSP配置
            $source = Get-ItemProperty $cspSourcePathWow
            $source.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
                Set-ItemProperty -Path $cspTargetPathWow -Name $_.Name -Value $_.Value
                Write-Host "  复制: $($_.Name) = $($_.Value)" -ForegroundColor Gray
            }
            
            Write-Host "  ✓ WOW6432Node CSP别名创建完成" -ForegroundColor Green
        }
        
        if (Test-Path $cspSourcePath) {
            Write-Host "从主路径复制CSP配置..." -ForegroundColor Cyan
            
            # 创建目标CSP路径
            if (-not (Test-Path $cspTargetPath)) {
                $parentPath = Split-Path $cspTargetPath -Parent
                if (-not (Test-Path $parentPath)) {
                    New-Item -Path $parentPath -Force | Out-Null
                }
                New-Item -Path $parentPath -Name "EnterSafe ePass3003 CSP" -Force | Out-Null
                Write-Host "  创建: $cspTargetPath" -ForegroundColor Green
            }
            
            # 复制CSP配置
            $source = Get-ItemProperty $cspSourcePath
            $source.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
                Set-ItemProperty -Path $cspTargetPath -Name $_.Name -Value $_.Value
                Write-Host "  复制: $($_.Name) = $($_.Value)" -ForegroundColor Gray
            }
            
            Write-Host "  ✓ 主路径CSP别名创建完成" -ForegroundColor Green
        }
        
        Write-Host ""
        Write-Host "✓ CSP别名创建成功！" -ForegroundColor Green
        Write-Host ""
        Write-Host "现在官方工具应该能够识别 'EnterSafe ePass3003 CSP' 并使用HZCA的DLL。" -ForegroundColor Green
    }
    
    "3" {
        Write-Host ""
        Write-Host "[2] 创建完整桥接..." -ForegroundColor Yellow
        Write-Host ""
        
        # 步骤1: 复制注册表配置
        Write-Host "步骤1: 复制注册表配置" -ForegroundColor Cyan
        if (Test-Path $sourcePathWow) {
            if (-not (Test-Path $targetPathWow)) {
                New-Item -Path "HKLM:\SOFTWARE\WOW6432Node\EnterSafe" -Name "ePass3003" -Force | Out-Null
            }
            $source = Get-ItemProperty $sourcePathWow
            $source.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
                Set-ItemProperty -Path $targetPathWow -Name $_.Name -Value $_.Value
            }
            Write-Host "  ✓ WOW6432Node 配置复制完成" -ForegroundColor Green
        }
        
        if (Test-Path $sourcePathMain) {
            if (-not (Test-Path $targetPathMain)) {
                New-Item -Path "HKLM:\SOFTWARE\EnterSafe" -Name "ePass3003" -Force | Out-Null
            }
            $source = Get-ItemProperty $sourcePathMain
            $source.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
                Set-ItemProperty -Path $targetPathMain -Name $_.Name -Value $_.Value
            }
            Write-Host "  ✓ 主路径配置复制完成" -ForegroundColor Green
        }
        
        # 步骤2: 创建CSP别名
        Write-Host ""
        Write-Host "步骤2: 创建CSP别名" -ForegroundColor Cyan
        if (Test-Path $cspSourcePathWow) {
            $parentPath = Split-Path $cspTargetPathWow -Parent
            if (-not (Test-Path $cspTargetPathWow)) {
                New-Item -Path $parentPath -Name "EnterSafe ePass3003 CSP" -Force | Out-Null
            }
            $source = Get-ItemProperty $cspSourcePathWow
            $source.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
                Set-ItemProperty -Path $cspTargetPathWow -Name $_.Name -Value $_.Value
            }
            Write-Host "  ✓ WOW6432Node CSP别名创建完成" -ForegroundColor Green
        }
        
        if (Test-Path $cspSourcePath) {
            $parentPath = Split-Path $cspTargetPath -Parent
            if (-not (Test-Path $cspTargetPath)) {
                New-Item -Path $parentPath -Name "EnterSafe ePass3003 CSP" -Force | Out-Null
            }
            $source = Get-ItemProperty $cspSourcePath
            $source.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
                Set-ItemProperty -Path $cspTargetPath -Name $_.Name -Value $_.Value
            }
            Write-Host "  ✓ 主路径CSP别名创建完成" -ForegroundColor Green
        }
        
        Write-Host ""
        Write-Host "=========================================" -ForegroundColor Green
        Write-Host "✓ 完整桥接创建成功！" -ForegroundColor Green
        Write-Host "=========================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "现在官方ePass3003管理工具应该能够:" -ForegroundColor Cyan
        Write-Host "  1. 读取设备配置（通过复制的注册表路径）" -ForegroundColor Gray
        Write-Host "  2. 识别CSP（通过CSP别名）" -ForegroundColor Gray
        Write-Host "  3. 管理HZCA设备（使用HZCA的DLL）" -ForegroundColor Gray
        Write-Host ""
        Write-Host "建议:" -ForegroundColor Yellow
        Write-Host "  - 先测试官方工具是否能识别设备" -ForegroundColor Gray
        Write-Host "  - 如果仍有问题，可能需要修改工具的设备识别逻辑" -ForegroundColor Gray
    }
    
    "4" {
        Write-Host ""
        Write-Host "[2] 移除桥接配置..." -ForegroundColor Yellow
        Write-Host ""
        
        Write-Host "警告: 这将删除所有官方路径下的配置" -ForegroundColor Red
        Write-Host -NoNewline "确认删除? (y/n): "
        $confirm = Read-Host
        
        if ($confirm -eq "y") {
            # 删除注册表配置
            foreach ($path in @($targetPathMain, $targetPathWow)) {
                if (Test-Path $path) {
                    Remove-Item -Path $path -Recurse -Force
                    Write-Host "  删除: $path" -ForegroundColor Yellow
                }
            }
            
            # 删除CSP别名
            foreach ($path in @($cspTargetPath, $cspTargetPathWow)) {
                if (Test-Path $path) {
                    Remove-Item -Path $path -Recurse -Force
                    Write-Host "  删除: $path" -ForegroundColor Yellow
                }
            }
            
            Write-Host ""
            Write-Host "✓ 桥接配置已移除" -ForegroundColor Green
        }
        else {
            Write-Host "操作已取消" -ForegroundColor Gray
        }
    }
    
    "5" {
        Write-Host "退出" -ForegroundColor Gray
        exit 0
    }
    
    default {
        Write-Host "无效选择" -ForegroundColor Red
        exit 1
    }
}

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "完成！" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "按任意键退出..."
Read-Host
