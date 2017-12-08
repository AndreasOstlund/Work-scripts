<#
	.SYNOPSIS
        Byter ut ett certifikat som är installeras i IIS.

	.DESCRIPTION
        Som standard byter scriptet ut (förnyar) ett certifikat med samma namn som det certifikat som pekas ut i parameter FilePath
        Scriptet returnerar ett objekt med information om gamla och nya certifikatet.
        Det kan användas vidare i andra scripts för att hämta upp certifikatinformation efter att certifikatet är bytt.

    .PARAMETER FilePath
        Anger sökväg till PKCS#12-fil med nytt certifikat och privat nyckel.

    .PARAMETER P12Password
        Anger lösenordet till PKCS#12-filen som pekas ut i parameter FilePath

    .PARAMETER WebSiteName
        Anger vilken site i IIS som certifikatet skall bytas på. Om inget anges är det "Default Web Site".

    .PARAMETER SkipCheckOldCert
        Om denna switch sätts kontrolleras inte först om certifikatet redan finns.

	.EXAMPLE

	.NOTES

	.LINK

#>
[CmdletBinding()]
Param(
#    [Parameter(Mandatory=$True)]
#    [string[]]$ComputerName,
    [Parameter(Mandatory=$True
               ,HelpMessage="En PKCS#12-fil med nytt certifikat.")]
    [string]$FilePath

	# borde vara secure string
    ,[Parameter(Mandatory=$True
                ,HelpMessage="Lösenordet till PKCS#12-filen som pekas ut i parameter FilePath")]
	[string]$P12Password

	,[Parameter(Mandatory=$False
               ,HelpMessage="Vilket site i IIS certifikatet skall bytas ut på. Om inget anges byts certifikatet på Default Web site.")]
    [string]$WebSiteName = "Default Web Site"

	,[Parameter(Mandatory=$False
               ,HelpMessage="Kontrollera inte befintligt certifikat.")]
	[switch]$SkipCheckOldCert

	,[Parameter(Mandatory=$False
               ,HelpMessage="Kopiera inte ACL:er från gamla certifikatet till nya.")]
	[switch]$SkipCopyACLs
)

# från http://stackoverflow.com/questions/20852807/setting-private-key-permissions-with-powershell
Function _Copy-CertificateACL {
    [cmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$source
        
        ,[Parameter(Mandatory=$true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$destination
    )

    #$keyPath = $env:ProgramData + "\Microsoft\Crypto\RSA\MachineKeys\";
    #$keyName = $source.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName;
    #$keyFullPath = $keyPath + $keyName

    $SourceKeyFilePath = Join-Path -Path $($env:ProgramData + "\Microsoft\Crypto\RSA\MachineKeys") -ChildPath $($source.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName)
    $DestKeyFilePath = Join-Path -Path $($env:ProgramData + "\Microsoft\Crypto\RSA\MachineKeys") -ChildPath $($destination.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName)


    #dir $SourceKeyFilePath 

    $SourceACL = Get-Acl -Path $SourceKeyFilePath 

    Write-Verbose "ACLs on source"
    $SourceACL.Access | ForEach-Object {
        Write-Verbose "$($_.IdentityReference) - $($_.FileSystemRights)"
    }

    try {
        Set-Acl -Path $DestKeyFilePath -AclObject $SourceACL -ErrorAction Stop
    } catch {
        Write-Warning "Something went wrong when setting ACL on new certificate!`r`nPlease check ACLs manually.`r`nError was:`r`n$($_.Exception.Message)"
    }

    try {
        $DestACL = Get-Acl -Path $DestKeyFilePath -ErrorAction Stop
    } catch {
        Write-Warning "Something went wrong when getting ACLs for the new certificate!`r`nPlease check ACLs manually.`r`nError was:`r`n$($_.Exception.Message)"
    }

    Write-Verbose "ACLs now on destination"
    $DestACL.Access | ForEach-Object {
        Write-Verbose "$($_.IdentityReference) - $($_.FileSystemRights)"
    }

}


#$VerbosePreference = "Continue"

import-module WebAdministration -Verbose:$False

if(-Not $(Test-Path -Path $FilePath) ) {
    Throw "Can't find $FilePath"
}

# Plocka ut fullständig sökväg till filen som spec'ats.
# Get-PFXCertificate verkar ha problem med relativa sökvägar av någon anledning.
$FilePath = (Get-ChildItem -Path $FilePath).FullName

# skapa ett return object som vi kommer populera med egenskaper för nya och gamla certifikatet.
$ReturnObject = New-Object -TypeName PSObject


################################################################
#
# Gör lite allmän felhantering först...
#

#
# Plocka ut den web site man valt att jobba med.
#
#$WebSiteName = "Default web site"
$website = dir iis:\sites | ? { $_.name -eq $WebSiteName }

if(-Not $WebSite) {
    Throw "Can't find website $WebSiteName"
}

if($((dir IIS:\SslBindings | ? { $_.Sites -eq $WebSiteName }).count) -gt 1)  {
    Throw "There is more than one SSL binding found for site $WebSiteName. This is currently not supported!"
}



#######################################################################################
#
# Let's get groovy...
#

try {

    # Get-PFXCertificate frågar efter password och det går inte att skicka in som parameter.
	#$newcert = Get-PFXCertificate -FilePath $FilePath -ErrorAction stop

    # http://stackoverflow.com/questions/14049002/how-to-fill-the-prompt-in-powershell-script
    # använder en .NET-klass istället.

    $newcert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $newcert.Import($FilePath,$P12Password,'DefaultKeySet')

}
catch {
	throw "Error executing Get-PFXCertificate. $_.Exception.Message"
}

if($newcert) {

	$CertCN = ""
	# Fulhack för att få ut Common Name. Plocka ut allt efter CN i subject, 
	#    splitta på "," och ta första elementet i returnerade array'en
	$CertCN = $newcert.subject.substring($newcert.subject.IndexOf("CN=")+3).Split(",")[0]
} else {
	throw "no certificate returned from Get-PFXCertificate"
}


if (-Not $SkipCheckOldCert) {

	$oldcert = dir Cert:\LocalMachine\My | ? { $_.Subject -like "*$($CertCN)*"}
	
	if(-Not $oldcert ) {
		throw "Cant find any certificate with name $CertCN!"
		
	} elseif($oldcert.count -gt 1) {
		throw "more than one certificate with name $CertCN found!`r`nCurrently replacing more than one cert is not supported!"
	}

    if($oldcert.Thumbprint -eq $newcert.Thumbprint) {
        Throw "Certificate in $FilePath and certificate found in store ($($newcert.Subject)) both seems to have the same thumbprint!`r`nUse switch parameter SkipCheckOldCert to replace anyway.`r`n"
        
    }

}


Write-Verbose "Importing $FilePath"

# kontrollera om vi är på windows 2012 R2, då finns cmdlet för att importera en p12'a
$OSVersion = Get-WmiObject Win32_OperatingSystem 
$importcmdlet = Get-Command Import-PfxCertificate -ErrorAction SilentlyContinue

if ( ($OSVersion.Caption -like "*Windows Server 2012*") -and ($importcmdlet) )  {

    Write-Verbose "Replacing with cmdlet for Windows server 2012"

    $securepwd = ConvertTo-SecureString -String $P12Password -AsPlainText -Force

    try {
        Get-ChildItem -Path $FilePath | Import-PfxCertificate -CertStoreLocation Cert:\LocalMachine\My -Password $securepwd -ErrorAction Stop
    }
    catch {
        Throw "Error importing $FilePath`r`n$($_.Exception.Message)"
    }


} else {
    Write-Verbose "Replacing with old certutil..."

    & certutil -importpfx -p $P12Password $FilePath NoExport

}


$newthumb = $newcert.Thumbprint.ToString()

Write-Verbose "Thumbprint of newly imported certificate: $($newthumb)"

# kolla om vi hittar nya certifikatet i store'et.
try {
	$importedcert = dir Cert:\LocalMachine\My\$newthumb -ErrorAction Stop
}
catch { 
	throw "$CertCN does not seem to have been imported correctly! Can't find it in store. Check that password is correct on command line."
}

if (-Not $SkipCheckOldCert) { write-verbose "Old certificate thumbprint: $($oldcert.ThumbPrint.ToString())" }
write-verbose "New certificate thumbprint: $newthumb"


# om vi har ett gammalt cert och vi inte har valt bort att kopiera ACL'er
if($oldcert -and -not $SkipCopyACLs) {
    # Här måste vi använda $importedcert som är objektet som har plockats ut från cert store EFTER att
    # nya certifikatet är importerat.
    # $newcert pekar till ett objekt som hämtades upp från P12-filen och kan inte användas för att sätta ACL'er!
    _Copy-CertificateACL -Source $oldcert -Destination $importedcert
}


# Nu fixar vi IIS...
#
# Här skulle det behöva fixas att verkligen kolla upp vilken binding som är kopplad till den site som är vald.
#



Push-Location IIS:\SslBindings
try {
	#$sslbinding = get-item IIS:\SslBindings\0.0.0.0!443 -ErrorAction stop

    # hitta de ssl-bindings som sitter kopplad till vald site
    $SSLBinding = Get-childitem IIS:\SslBindings | ? { $_.Sites -eq $WebSiteName }
}
catch {}

if(-Not $sslbinding) {
	# if we didn't get an SSLBinding, we assume there none configured
	New-WebBinding -Name $WebSiteName -IP * -Port 443 -Protocol https
	Get-Item Cert:\LocalMachine\My\$newthumb | New-Item .\0.0.0.0!443 -verbose
} else {

    # sätt det nya certifikatet på alla bindings vi hittade...
    $SSLBinding | ForEach-Object { Get-Item Cert:\LocalMachine\My\$newthumb | Set-Item $_.PSPath -Verbose }

	#Get-Item Cert:\LocalMachine\My\$newthumb | Set-Item .\0.0.0.0!443 -verbose
}

#$newsslbinding = get-item IIS:\SslBindings\0.0.0.0!443
$newsslbinding = Get-childitem IIS:\SslBindings | ? { $_.Sites -eq $WebSiteName }

if($($newsslbinding.Thumbprint.ToString()) -ne $newthumb ) {
	pop-location
	throw "Somthing might have gone wrong setting binding in IIS!`r`nThumbprint on IIS SSL binding does not match newly imported certificate!We are in limbo! Please manually check certificates!`r`n"
}

pop-location

Push-Location Cert:\LocalMachine\My

if (-Not $SkipCheckOldCert) {
	$oldthumb = $oldcert.ThumbPrint.ToString()
	# -DeleteKey verkar inte funka på powershell 2.0
	try {
		Get-Item Cert:\LocalMachine\My\$oldthumb | Remove-Item -DeleteKey -ErrorAction Stop
	}
	catch {
		Write-Warning "Could not delete old certificate and key. It must be remove manually!`r`nAlso please check installed powershell version to support removal of cert and key.`r`nError message: $($_.Exception.Message)"
	}
}


$ReturnObject | Add-Member -MemberType NoteProperty -Name OldCertificate -Value $oldcert
$ReturnObject | Add-Member -MemberType NoteProperty -Name NewCertificate -Value $importedcert


pop-location



# output return object
$ReturnObject
