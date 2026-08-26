# 分析 GP_ADM_LNCA.exe 如何调用 USBKey_Reset

## 方法：搜索 GP_ADM_LNCA.exe 中对 USBKey_Reset 的引用

$exePath = "G:\Codes\USBKeyDriver\Library\LNCA\GP_ADM_LNCA.exe"
$bytes = [System.IO.File]::ReadAllBytes($exePath)

Write-Host "分析: $exePath"
Write-Host "文件大小: $($bytes.Length) 字节`n"

# 搜索 "USBKey_Reset" 字符串引用
$pattern = [System.Text.Encoding]::ASCII.GetBytes("USBKey_Reset")
Write-Host "搜索字符串引用..."

for ($i = 0; $i -lt $bytes.Length - $pattern.Length; $i++) {
    $match = $true
    for ($j = 0; $j -lt $pattern.Length; $j++) {
        if ($bytes[$i + $j] -ne $pattern[$j]) {
            $match = $false
            break
        }
    }
    
    if ($match) {
        Write-Host "`n找到 'USBKey_Reset' 在偏移: 0x$($i.ToString('X'))"
        
        # 显示周围64字节
        $start = [Math]::Max(0, $i - 32)
        $end = [Math]::Min($bytes.Length - 1, $i + 32)
        
        Write-Host "周围代码/数据:"
        for ($k = $start; $k -le $end; $k += 16) {
            $lineEnd = [Math]::Min($k + 15, $end)
            $hex = ($bytes[$k..$lineEnd] | ForEach-Object { $_.ToString('X2') }) -join ' '
            Write-Host "  0x$($k.ToString('X6')): $hex"
        }
    }
}

Write-Host "`n搜索完成"
