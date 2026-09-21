# ePass3003 HZCA Device Verification Script
# Check CSP, Registry and Certificate Store

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "ePass3003 HZCA Device Verification" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check Registry Paths
Write-Host "[1] Checking Registry Configuration..." -ForegroundColor Yellow
Write-Host ""

$regPaths = @(
    @{Name="Official Version"; Path="HKLM:\SOFTWARE\EnterSafe\ePass3003"},
    @{Name="HZCA Version"; Path="HKLM:\SOFTWARE\EnterSafe\ePass3003_HCCB"},
    @{Name="Official (WOW6432)"; Path="HKLM:\SOFTWARE\WOW6432Node\EnterSafe\ePass3003"},
    @{Name="HZCA (WOW6432)"; Path="HKLM:\SOFTWARE\WOW6432Node\EnterSafe\ePass3003_HCCB"}
)

foreach ($item in $regPaths) {
    Write-Host "  Checking: $($item.Name)" -NoNewline
    try {
        $key = Get-ItemProperty $item.Path -ErrorAction Stop
        Write-Host " [FOUND]" -ForegroundColor Green
        Write-Host "    Path: $($item.Path)" -ForegroundColor Gray
        
        $key.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
            Write-Host "      $($_.Name) = $($_.Value)" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host " [NOT FOUND]" -ForegroundColor DarkGray
    }
}

Write-Host ""

# 2. Check CSP Registration
Write-Host "[2] Checking CSP Registration..." -ForegroundColor Yellow
Write-Host ""

$cspBasePath = "HKLM:\SOFTWARE\Microsoft\Cryptography\Defaults\Provider"
$cspBasePath64 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Defaults\Provider"

$cspNames = @(
    "EnterSafe ePass3003 CSP",
    "EnterSafe ePass3003 CSP For HCCB V1.0"
)

foreach ($cspName in $cspNames) {
    Write-Host "  Checking CSP: $cspName" -NoNewline
    
    $found = $false
    foreach ($basePath in @($cspBasePath, $cspBasePath64)) {
        $path = Join-Path $basePath $cspName
        if (Test-Path $path) {
            $cspInfo = Get-ItemProperty $path -ErrorAction SilentlyContinue
            Write-Host " [FOUND]" -ForegroundColor Green
            Write-Host "    Path: $path" -ForegroundColor Gray
            if ($cspInfo.Image) {
                Write-Host "    DLL: $($cspInfo.Image)" -ForegroundColor Gray
            }
            if ($cspInfo.Type) {
                Write-Host "    Type: $($cspInfo.Type)" -ForegroundColor Gray
            }
            $found = $true
            break
        }
    }
    
    if (-not $found) {
        Write-Host " [NOT FOUND]" -ForegroundColor DarkGray
    }
}

Write-Host ""

# 3. Check Certificate Store
Write-Host "[3] Checking Certificate Store..." -ForegroundColor Yellow
Write-Host ""

$certScript = @'
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

public class CertChecker {
    public static void CheckCertificates() {
        var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        try {
            store.Open(OpenFlags.ReadOnly);
            
            int totalCerts = 0;
            int ePassCerts = 0;
            
            foreach (X509Certificate2 cert in store.Certificates) {
                totalCerts++;
                
                try {
                    if (cert.HasPrivateKey) {
                        var key = cert.PrivateKey as RSACryptoServiceProvider;
                        if (key != null) {
                            var cspInfo = key.CspKeyContainerInfo;
                            
                            if (cspInfo.ProviderName.Contains("ePass3003") || 
                                cspInfo.ProviderName.Contains("HCCB")) {
                                ePassCerts++;
                                
                                Console.WriteLine("  ePass3003 Certificate Found:");
                                Console.WriteLine("    Subject: " + cert.Subject);
                                Console.WriteLine("    Issuer: " + cert.Issuer);
                                Console.WriteLine("    Serial: " + cert.SerialNumber);
                                Console.WriteLine("    Valid: " + cert.NotBefore.ToString("yyyy-MM-dd") + " to " + cert.NotAfter.ToString("yyyy-MM-dd"));
                                Console.WriteLine("    CSP Provider: " + cspInfo.ProviderName);
                                Console.WriteLine("    Container: " + cspInfo.KeyContainerName);
                                Console.WriteLine("    KeySpec: " + cspInfo.KeyNumber);
                                Console.WriteLine("");
                            }
                        }
                    }
                } catch {
                }
            }
            
            Console.WriteLine("  Certificate Summary:");
            Console.WriteLine("    Total Certificates: " + totalCerts);
            Console.WriteLine("    ePass3003 Certificates: " + ePassCerts);
            
        } finally {
            store.Close();
        }
    }
}
'@

try {
    Add-Type -TypeDefinition $certScript -ReferencedAssemblies @("System.Security")
    [CertChecker]::CheckCertificates()
}
catch {
    Write-Host "  Certificate check failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""

# 4. Check USB Devices
Write-Host "[4] Checking USB Devices..." -ForegroundColor Yellow
Write-Host ""

$usbDevices = Get-PnpDevice | Where-Object { 
    $_.Class -eq "SmartCardReader" -or 
    $_.FriendlyName -like "*ePass*" -or 
    $_.FriendlyName -like "*EnterSafe*"
}

if ($usbDevices) {
    foreach ($device in $usbDevices) {
        Write-Host "  Device: $($device.FriendlyName)" -ForegroundColor Green
        Write-Host "    Status: $($device.Status)" -ForegroundColor Gray
        Write-Host "    Class: $($device.Class)" -ForegroundColor Gray
        Write-Host "    Instance ID: $($device.InstanceId)" -ForegroundColor Gray
        Write-Host ""
    }
}
else {
    Write-Host "  No related USB devices found" -ForegroundColor DarkGray
}

# 5. Check Smart Card Service
Write-Host "[5] Checking Smart Card Service..." -ForegroundColor Yellow
Write-Host ""

$service = Get-Service -Name "SCardSvr" -ErrorAction SilentlyContinue
if ($service) {
    $color = if($service.Status -eq "Running"){"Green"}else{"Yellow"}
    Write-Host "  Smart Card Service (SCardSvr): $($service.Status)" -ForegroundColor $color
}

Write-Host ""

# 6. Check Tool Files
Write-Host "[6] Checking Management Tool Files..." -ForegroundColor Yellow
Write-Host ""

$toolPaths = @(
    "g:\Codes\USBKeyDriver\Library\ePass3003 USB Tool\shuttle_certd3003.exe",
    "g:\Codes\USBKeyDriver\Library\ePass3003 USB Tool\ePassManager_3003.exe",
    "g:\Codes\USBKeyDriver\Library\ePass3003 HZCA SDK\HZBANK_certd3003.exe"
)

foreach ($toolPath in $toolPaths) {
    $exists = Test-Path $toolPath
    $name = Split-Path $toolPath -Leaf
    Write-Host "  $name" -NoNewline
    if ($exists) {
        $size = (Get-Item $toolPath).Length
        $sizeKB = [math]::Round($size/1KB, 2)
        Write-Host " [EXISTS, $sizeKB KB]" -ForegroundColor Green
    }
    else {
        Write-Host " [NOT EXISTS]" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "Verification Complete!" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
