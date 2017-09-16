#https://stackoverflow.com/questions/36775331/extract-certificate-from-sys-file
$DriverPath =  "$env:temp\{73021f6f-ccfd-144d-af44-cf7e9e1f7404}\tap0901.cat"
$exportType = [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert
Get-AuthenticodeSignature -FilePath $DriverPath  | select *

$SignCert = (Get-AuthenticodeSignature -FilePath $DriverPath).SignerCertificate
$SignCert

[System.IO.File]::WriteAllBytes("openssl_tap.cer",$SignCert.Export($exportType))

#https://social.technet.microsoft.com/Forums/en-US/37a213b9-f185-482e-b610-295f2056506e/export-certificate-using-base-64-cer-format-with-powershell-?forum=winserversecurity
certutil -encode openssl_tap.cer openssl_tap.pem



