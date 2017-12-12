# Modified from https://gist.github.com/E000001/a560022c6ece7efcd2ebcfb398396757
<#
#Ecrypt and Decrypt Examples
$key = Create-AesKey(Read-Host "Write Password:")
write-host "Created Key for AES" $key
$unencryptedString = "TopSecretStringHere:)"
$encryptedString = Encrypt-String $key $unencryptedString
write-host "Encrypted String:" $encryptedString
$backToPlainText = Decrypt-String $key $encryptedString
write-host "Decrypted String:" $backToPlainText
#>

$key = Create-AesKey(Read-Host "Write Password:")
write-host "Created Key for AES" $key
$unencryptedString = Get-Content -path .\Install-WorkClient.ps1 -Raw
$encryptedString = Encrypt-String $key $unencryptedString
write-host "Encrypted String:" $encryptedString
$backToPlainText = Decrypt-String $key $encryptedString
write-host "Decrypted String:" $backToPlainText


function Create-AESKey($key){
    $r = new-Object System.Security.Cryptography.AesManaged
    $pass = [Text.Encoding]::UTF8.GetBytes($key) 
    $salt = [Text.Encoding]::UTF8.GetBytes("saltnpeppermakesmyday")
    $r.Key = (new-Object Security.Cryptography.PasswordDeriveBytes $pass, $salt, "SHA1", 5).GetBytes(32) #256/8
    $r.Key
}


function Create-AesManagedObject($key, $IV) {
    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 256
    if ($IV) {
        if ($IV.getType().Name -eq "String") {
            $aesManaged.IV = [System.Convert]::FromBase64String($IV)
        }
        else {
            $aesManaged.IV = $IV
        }
    }
    if ($key) {
        if ($key.getType().Name -eq "String") {
            $aesManaged.Key = [System.Convert]::FromBase64String($key)
        }
        else {
            $aesManaged.Key = $key
        }
    }
    $aesManaged
}

function Create-AesKey() {
    $aesManaged = Create-AesManagedObject
    $aesManaged.GenerateKey()
    [System.Convert]::ToBase64String($aesManaged.Key)
}

function Encrypt-String($key, $unencryptedString) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($unencryptedString)
    $aesManaged = Create-AesManagedObject $key
    $encryptor = $aesManaged.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
    [byte[]] $fullData = $aesManaged.IV + $encryptedData
    $aesManaged.Dispose()
    [System.Convert]::ToBase64String($fullData)
}

function Decrypt-String($key, $encryptedStringWithIV) {
    $bytes = [System.Convert]::FromBase64String($encryptedStringWithIV)
    $IV = $bytes[0..15]
    $aesManaged = Create-AesManagedObject $key $IV
    $decryptor = $aesManaged.CreateDecryptor();
    $unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16);
    $aesManaged.Dispose()
    [System.Text.Encoding]::UTF8.GetString($unencryptedData).Trim([char]0)
}


