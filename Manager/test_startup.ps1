$ErrorActionPreference = "Continue"
$exe = "G:\Codes\USBKeyDriver\Manager\src\USBKey.Manager\bin\Debug\net8.0-windows\win-x86\USBKey.Manager.exe"

Write-Host "========== 启动 USB Key 管理器 ==========" -ForegroundColor Cyan

# 启动进程并等待 5 秒
$process = Start-Process -FilePath $exe -PassThru -WindowStyle Normal

Write-Host "进程 ID: $($process.Id)" -ForegroundColor Yellow
Write-Host "等待 5 秒检查程序是否崩溃..." -ForegroundColor Yellow

Start-Sleep -Seconds 5

if ($process.HasExited) {
    Write-Host "❌ 程序已退出，退出代码: $($process.ExitCode)" -ForegroundColor Red
} else {
    Write-Host "✅ 程序正常运行中 (PID: $($process.Id))" -ForegroundColor Green
    Write-Host "准备关闭程序..." -ForegroundColor Yellow
    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    Write-Host "程序已关闭" -ForegroundColor Green
}

Write-Host "========== 测试完成 ==========" -ForegroundColor Cyan
