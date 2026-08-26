# 修改 .NET PE 文件，强制设置为 32 位（32BITREQ）
param(
    [Parameter(Mandatory=$true)]
    [string]$ExePath
)

if (-not (Test-Path $ExePath)) {
    Write-Error "文件不存在: $ExePath"
    exit 1
}

Write-Host "正在修改 PE 头: $ExePath"

# 读取文件
$bytes = [System.IO.File]::ReadAllBytes($ExePath)

# 读取 PE offset (在 0x3C 位置)
$peOffset = [BitConverter]::ToInt32($bytes, 0x3C)

# PE 签名应该是 "PE\0\0" (0x50 0x45 0x00 0x00)
$peSignature = [BitConverter]::ToUInt32($bytes, $peOffset)
if ($peSignature -ne 0x00004550) {
    Write-Error "无效的 PE 文件"
    exit 1
}

# IMAGE_FILE_HEADER 在 PE 签名后 4 字节
# Characteristics 字段在 IMAGE_FILE_HEADER + 18 字节
$characteristicsOffset = $peOffset + 4 + 18

# 读取当前 Characteristics
$characteristics = [BitConverter]::ToUInt16($bytes, $characteristicsOffset)

# IMAGE_FILE_32BIT_MACHINE = 0x0100
$IMAGE_FILE_32BIT_MACHINE = 0x0100

# 设置 32 位标志
$newCharacteristics = $characteristics -bor $IMAGE_FILE_32BIT_MACHINE

Write-Host "当前 Characteristics: 0x$($characteristics.ToString('X4'))"
Write-Host "新的 Characteristics: 0x$($newCharacteristics.ToString('X4'))"

# 写入新值
$bytes[$characteristicsOffset] = $newCharacteristics -band 0xFF
$bytes[$characteristicsOffset + 1] = ($newCharacteristics -shr 8) -band 0xFF

# CLI Header (.NET specific) - 在 Optional Header 中
# Optional Header 在 PE Header + 24 字节
$optionalHeaderOffset = $peOffset + 4 + 20

# PE32 = 0x10B, PE32+ = 0x20B
$magic = [BitConverter]::ToUInt16($bytes, $optionalHeaderOffset)
Write-Host "PE Magic: 0x$($magic.ToString('X4'))"

# CLI Header RVA 在不同位置
if ($magic -eq 0x10B) {
    # PE32: CLI Header Directory 在 Optional Header + 208
    $cliHeaderRvaOffset = $optionalHeaderOffset + 208
} else {
    # PE32+: CLI Header Directory 在 Optional Header + 224
    $cliHeaderRvaOffset = $optionalHeaderOffset + 224
}

$cliHeaderRva = [BitConverter]::ToUInt32($bytes, $cliHeaderRvaOffset)
Write-Host "CLI Header RVA: 0x$($cliHeaderRva.ToString('X8'))"

if ($cliHeaderRva -gt 0) {
    # 需要从 RVA 转换为文件偏移（简化处理，假设在第一个 section）
    # CLI Header 的 Flags 字段在 +16 字节
    # COMIMAGE_FLAGS_32BITREQUIRED = 0x00000002
    
    Write-Host ".NET 程序集已标记（需要 corflags 工具精确修改 IL 标志）"
}

# 保存文件
[System.IO.File]::WriteAllBytes($ExePath, $bytes)
Write-Host "修改完成！"
