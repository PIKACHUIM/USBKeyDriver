$cert = New-SelfSignedCertificate -Subject "CN=LNCA Test" -Type CodeSigningCert -CertStoreLocation Cert:\CurrentUser\My
$pwd = ConvertTo-SecureString -String "123456" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath "test-lnca.pfx" -Password $pwd
Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)"
Write-Host "test-lnca.pfx 已生成，密码 123456"
