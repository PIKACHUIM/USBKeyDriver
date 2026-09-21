# DumpExports.ps1 - 解析 PE 导出表（无需 dumpbin/依赖）
# 用法: powershell -File DumpExports.ps1 <dll路径> [关键字过滤]
param(
    [Parameter(Mandatory=$true)][string]$DllPath,
    [string]$Filter = ""
)

function Dump-Exports {
    param([string]$path)
    $bytes = [System.IO.File]::ReadAllBytes($path)
    $br = New-Object System.IO.BinaryReader((New-Object System.IO.MemoryStream(,$bytes)))

    # DOS header
    $br.BaseStream.Position = 0x3C
    $peOffset = $br.ReadInt32()

    # PE signature
    $br.BaseStream.Position = $peOffset
    if ($br.ReadUInt32() -ne 0x00004550) { throw "Not a PE file" }

    # COFF header
    $machine = $br.ReadUInt16()
    $numSections = $br.ReadUInt16()
    $br.BaseStream.Position += 12  # TimeDateStamp, PtrToSymbolTable, NumSymbols
    $optHeaderSize = $br.ReadUInt16()
    $characteristics = $br.ReadUInt16()

    # Optional header
    $optStart = $br.BaseStream.Position
    $magic = $br.ReadUInt16()
    $is64 = ($magic -eq 0x20B)

    # Data directories: PE32 -> offset 96, PE32+ -> offset 112
    if ($is64) {
        $br.BaseStream.Position = $optStart + 112
    } else {
        $br.BaseStream.Position = $optStart + 96
    }
    $exportRva = $br.ReadInt32()
    $exportSize = $br.ReadInt32()

    if ($exportRva -eq 0) { Write-Output "(no export table)"; return }

    # Section headers (after optional header)
    $sectionStart = $optStart + $optHeaderSize
    $sections = @()
    for ($i=0; $i -lt $numSections; $i++) {
        $br.BaseStream.Position = $sectionStart + ($i * 40)
        $nameBytes = $br.ReadBytes(8)
        $name = [System.Text.Encoding]::ASCII.GetString($nameBytes).TrimEnd([char]0)
        $br.BaseStream.Position += 4   # VirtualSize
        $virtAddr = $br.ReadInt32()
        $rawSize = $br.ReadInt32()
        $rawAddr = $br.ReadInt32()
        $sections += [PSCustomObject]@{ Name=$name; VA=$virtAddr; RawSize=$rawSize; RawAddr=$rawAddr }
    }

    # RVA -> file offset
    function RvaToOffset([int]$rva) {
        foreach ($s in $sections) {
            if ($rva -ge $s.VA -and $rva -lt ($s.VA + $s.RawSize)) {
                return $rva - $s.VA + $s.RawAddr
            }
        }
        return -1
    }

    # Export directory
    $expOffset = RvaToOffset $exportRva
    if ($expOffset -lt 0) { Write-Output "(cannot resolve export RVA)"; return }

    $br.BaseStream.Position = $expOffset
    $br.BaseStream.Position += 12  # Characteristics, TimeDateStamp, Major/Minor
    $nameRva = $br.ReadInt32()
    $ordBase = $br.ReadInt32()
    $numFuncs = $br.ReadInt32()
    $numNames = $br.ReadInt32()
    $addrFuncsRva = $br.ReadInt32()
    $addrNamesRva = $br.ReadInt32()
    $addrOrdsRva = $br.ReadInt32()

    $dllNameOffset = RvaToOffset $nameRva
    $br.BaseStream.Position = $dllNameOffset
    $dllName = ""
    while ($true) { $c = $br.ReadByte(); if ($c -eq 0) { break }; $dllName += [char]$c }
    Write-Output ("DLL: {0}  ({1}-bit, {2} exports, {3} named)" -f $dllName, $(if($is64){"64"}else{"32"}), $numFuncs, $numNames)

    # Read name RVAs
    $namesOff = RvaToOffset $addrNamesRva
    $ordsOff = RvaToOffset $addrOrdsRva
    $funcsOff = RvaToOffset $addrFuncsRva

    $names = @()
    for ($i=0; $i -lt $numNames; $i++) {
        $br.BaseStream.Position = $namesOff + ($i * 4)
        $nRva = $br.ReadInt32()
        $nOff = RvaToOffset $nRva
        $br.BaseStream.Position = $nOff
        $n = ""
        while ($true) { $c = $br.ReadByte(); if ($c -eq 0) { break }; $n += [char]$c }

        $br.BaseStream.Position = $ordsOff + ($i * 2)
        $ordinal = $br.ReadUInt16()

        $br.BaseStream.Position = $funcsOff + ($ordinal * 4)
        $funcRva = $br.ReadInt32()

        if ($Filter -eq "" -or $n -match $Filter) {
            $names += [PSCustomObject]@{ Ordinal=($ordinal + $ordBase); Name=$n; RVA=("0x{0:X8}" -f $funcRva) }
        }
    }

    $names | Sort-Object Name | ForEach-Object { "{0,4}  0x{1}  {2}" -f $_.Ordinal, $_.RVA, $_.Name }
}

Dump-Exports $DllPath
