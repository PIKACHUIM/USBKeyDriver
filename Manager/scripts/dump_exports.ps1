# 读取 DLL 导出函数
param([string]$DllPath)

$bytes = [System.IO.File]::ReadAllBytes($DllPath)

# 读取 PE header offset
$peOffset = [BitConverter]::ToInt32($bytes, 0x3C)

# 读取 Optional Header 的 Magic (PE32/PE32+)
$magic = [BitConverter]::ToUInt16($bytes, $peOffset + 4 + 20)

# 导出表 RVA 位置
if ($magic -eq 0x10B) {
    # PE32
    $exportDirRvaOffset = $peOffset + 4 + 20 + 96
} else {
    # PE32+
    $exportDirRvaOffset = $peOffset + 4 + 20 + 112
}

$exportDirRva = [BitConverter]::ToUInt32($bytes, $exportDirRvaOffset)
$exportDirSize = [BitConverter]::ToUInt32($bytes, $exportDirRvaOffset + 4)

if ($exportDirRva -eq 0) {
    Write-Host "无导出函数"
    exit
}

# 简化处理：从 RVA 转文件偏移（假设在第一个 section）
$sectionHeaderOffset = $peOffset + 4 + 20 + ($magic -eq 0x10B ? 224 : 240)

$sectionVirtualAddress = [BitConverter]::ToUInt32($bytes, $sectionHeaderOffset + 12)
$sectionPointerToRawData = [BitConverter]::ToUInt32($bytes, $sectionHeaderOffset + 20)

$exportDirOffset = $exportDirRva - $sectionVirtualAddress + $sectionPointerToRawData

# 读取导出表信息
$numberOfNames = [BitConverter]::ToUInt32($bytes, $exportDirOffset + 24)
$addressOfNamesRva = [BitConverter]::ToUInt32($bytes, $exportDirOffset + 32)

$addressOfNamesOffset = $addressOfNamesRva - $sectionVirtualAddress + $sectionPointerToRawData

Write-Host "`n[$DllPath] 导出函数 ($numberOfNames):`n"

for ($i = 0; $i -lt $numberOfNames; $i++) {
    $nameRva = [BitConverter]::ToUInt32($bytes, $addressOfNamesOffset + $i * 4)
    $nameOffset = $nameRva - $sectionVirtualAddress + $sectionPointerToRawData
    
    # 读取字符串
    $nameBytes = @()
    $pos = $nameOffset
    while ($bytes[$pos] -ne 0) {
        $nameBytes += $bytes[$pos]
        $pos++
    }
    
    $name = [System.Text.Encoding]::ASCII.GetString($nameBytes)
    Write-Host "  $name"
}
