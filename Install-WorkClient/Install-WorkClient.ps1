Function New-DirectoryIfNotExists($dirname) {

    if(-not $(Test-Path -Path $dirname)) { mkdir $dirname }
}


Function New-ProgramShortcut {
    [cmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$TargetPath

        ,[Parameter(Mandatory=$True)]
        [string]$IconFileName

        ,[Parameter(Mandatory=$False)]
        [string]$WorkingDirectory

        ,[Parameter()]
        [switch]$AllUsers
    )

<#
set WshShell = CreateObject("Wscript.shell")
strDesktop = WshShell.SpecialFolders("AllUsersDesktop")
set oMyShortcut = WshShell.CreateShortcut(strDesktop + "\IIS Manager.lnk")
'set oMyShortcut = WshShell.CreateShortcut("C:\Users\Public\Desktop\odbcad32.lnk")
'oMyShortcut.WindowStyle = 3  &&Maximized 7=Minimized  4=Normal 
'oMyShortcut.IconLocation = "C:\myicon.ico"
OMyShortcut.TargetPath = "%windir%\system32\inetsrv\InetMgr.exe"
'oMyShortCut.Hotkey = "ALT+CTRL+F"
oMyShortCut.Save
#>
        # check if icon filename ends with lnk
        if(-Not $($IconFileName -match ".lnk$") ) {
            Write-Warning "Appending .lnk to icon filename $IconFileName"
            $IconFileName += ".lnk"
        }



        $ShellObj = New-Object -ComObject WScript.Shell

        if($AllUsers) {
            $DekstopPath = $ShellObj.SpecialFolders("AllUsersDesktop")
        
        } else {
            $DekstopPath = Join-Path -Path $env:USERPROFILE -ChildPath "Desktop"
        
        }

        Write-Verbose "Creating desktop icon $IconFileName in $DesktopPath"

        $ShortCut = $ShellObj.CreateShortcut( $(Join-Path -Path $DekstopPath -ChildPath $IconFileName) )
        $ShortCut.TargetPath = $TargetPath

        if($WorkingDirectory) {
            $ShortCut.WorkingDirectory = $WorkingDirectoryd
        }

        $ShortCut.Save()

        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($ShellObj) | Out-Null
        Remove-Variable ShellObj

}



Function ConvertTo-LowercasePathQualifier($path) {

    $Qualifier = Split-Path -Path $path -Qualifier
    $PathNoQualifier = Split-Path -Path $path -NoQualifier

    return ($Qualifier.ToLower())+$PathNoQualifier

}

Function ConvertTo-WSLPath($path) {

    $wslpath = ConvertTo-LowercasePathQualifier -path $path

    return ("/mnt/"+$wslpath).Replace(':','').Replace('\','/')
}


Function _Expand-VariablesInString {
    [cmdletBinding()]
    Param(
        [Parameter(Mandatory=$True
                  ,ValueFromPipeline=$True)]
        [string]$Inputstring,

        [Parameter(Mandatory=$True)]
        [hashtable]$VariableMappings
    )


    foreach($key in $Variablemappings.Keys) {

        $InputString = $Inputstring.Replace("%"+$key+"%",$VariableMappings[$key])
    }


    return $Inputstring
}


Function Install-WorkClient() {
    [cmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    [string]$PrivDir
    ,[Parameter(Mandatory=$True)]
    [string]$CorpRepo
    )

    $RebootIt = $False

    # https://stackoverflow.com/questions/34331206/ignore-ssl-warning-with-powershell-downloadstring
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
    # https://stackoverflow.com/questions/36265534/invoke-webrequest-ssl-fails
    $AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy







    ############################################
    # Create Directories
    New-DirectoryIfNotExists -dirname $privdir
    $subdirs = @("_down","install_logs","scheduled_scripts","tools","local_code","local_code\vagrant","temp","greenshot")
    $subdirs | ForEach-Object {
        New-DirectoryIfNotExists -dirname $(Join-Path -Path $privdir -ChildPath $_) 
    }

    $GreenshotConfigDir = $(Join-Path -Path $env:APPDATA -ChildPath "Greenshot")
    if(-not $(Test-Path -Path $GreenshotConfigDir)) { mkdir $GreenshotConfigDir }
    copy -Path .\customizations\Greenshot.ini -Destination $GreenshotConfigDir









    #################################################
    # Windows features
    $Features = @(
        @{
            FeatureName="Microsoft-Hyper-V"
            All = $TRue
        },
        @{
            FeatureName="Microsoft-Windows-Subsystem-Linux"
            All = $False
        };
    )

    $Features | ForEach-Object {
        $feature = $_
        $status = Get-WindowsOptionalFeature -Online -FeatureName $feature.FeatureName
        if(-not $($feature.State -eq "Enabled") ) {
            $InstallStatus = Enable-WindowsOptionalFeature -Online -FeatureName $feature.FeatureName -All:$($feature.All -eq $TRue) -NoRestart -Verbose
            if($InstallStatus.RestartNeeded) {
                $RebootIt = $true
            }
        }
    }



    



    ######################################
    # Chrome
    $package = Get-Package -ProviderName msi -Name "Google Chrome" -ErrorAction Continue
    if(-not $package) {
        & msiexec /i $privdir\_down\googlechromestandaloneenterprise64.msi /passive /log $privdir\install_logs\chrome_install.log
    }







    ########################################################
    # RSAT for windows 10. KB2693643
    $rsat = get-hotfix -Id KB2693643
    if(-not $rsat) {
        Start-Process -FilePath C:\Windows\System32\wusa.exe -ArgumentList "$privdir\_down\WindowsTH-RSAT_WS2016-x64.msu /quiet /norestart /log:$privdir\install_logs\rsat_install.log" -WindowStyle Hidden -Wait
        $RebootIt = $true
    }

    Remove-Item -Path HKCU:\SOFTWARE\Policies\Google -Force -Recurse 




















    

    ###################################
    # Create login script
    #
$LoginSCript=@'
Get-process Driftinformation | stop-process
Remove-Item -Path HKCU:\SOFTWARE\Policies\Google -Force -Recurse
Remove-Item -Path HKLM:\SOFTWARE\Policies\Google -Force -Recurse
Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name "Driftinfo"
'@


Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name "Driftinfo"
  

    $LoginSCriptPath = "$privdir\scheduled_scripts\logon_script.ps1"
    $LoginSCript | Set-Content -Path $LoginSCriptPath -Encoding UTF8 

    $SChedTask = Get-ScheduledTask -TaskName "Logon script" -TaskPath '\'


    if(-not $SChedTask) {
        #$SchedTrigger = New-ScheduledTaskTrigger -AtLogOn
        $SchedAction = New-ScheduledTaskAction -Execute powershell.exe -Argument "-NoLogo -NonInteractive -WindowStyle Hidden -ExecutionPolicy UnRestricted -File $LogonSCriptPath -WorkingDirectory $privdir\scheduled_scripts\"
        $SChedSettings = New-ScheduledTaskSettingsSet
        $SChedTask = New-ScheduledTask -Action $SchedAction -Trigger $SchedTrigger -Description "Custom logon script" -Settings $SChedSettings
        Register-ScheduledTask -TaskName "Logon script" -InputObject $SChedTask -TaskPath "\"
    }

    if($RebootIt) {
        Restart-Computer -Force
    }



    


    #################################################
    # Sysinternals
    #
    $SysinternalsAppDir = join-path -path $env:ProgramFiles -ChildPath "sysinternals"
    Invoke-WebRequest -Uri "https://download.sysinternals.com/files/SysinternalsSuite.zip" -OutFile $privdir\_down\sysinternals.zip
    Unblock-File -Path $privdir\_down\sysinternals.zip
    remove-Item -Path $SysinteralsAppDir -Force
    Expand-Archive -Path $privdir\_down\sysinternals.zip -DestinationPath $SysinternalsAppDir -Force
    & "$($SysinternalsAppDir)\procexp.exe" -accepteula

    New-ProgramShortcut -TargetPath $(Join-Path -Path $SysinternalsAppDir -ChildPath "procexp.exe") -IconFileName "Sysinternals"



    #########################################
    # linux Subsystem for windows
    #
    # enable developer mode for lInux subsystem
    New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock -Name AllowDevelopmentWithoutDevLicense -PropertyType DWord -Value 1 -Force

    Start-Process -FilePath C:\Windows\System32\cmd.exe -ArgumentList "/c `"lxrun /install /y`"" -NoNewWindow -Wait
    # initially set default user as root
    Start-Process -FilePath C:\Windows\System32\cmd.exe -ArgumentList "/c `"lxrun /setdefaultuser root /y`"" -NoNewWindow -Wait



    # WSL path 
    # ii $env:LOCALAPPDATA\lxss\rootfs\etc\default
    # $env:LOCALAPPDATA\lxss\rootfs\etc\default
    # to set locale
    # sudo update-locale LANG=en_US.UTF8
    # cat /etc/default/locale
    # LANG=en_US.UTF8

    # WSL set $env:computername to 127.0.0.1 in /etc/hosts


$WSLInitPrivScript=@'
#!/bin/sh

/usr/sbin/update-locale LANG=en_US.UTF8

########################################
# package install
# python-dev for pip
# libffi-dev for ansible
# libssl-dev for ansible
apt-get --assume-yes install vim git tmux python-pip python-dev libffi-dev libssl-dev pwgen python-virtualenv jq
#pip install ansible
#boto is needed by ec2 module
#pip install boto
# github3.py needed by github_release module
#pip install github2 github3.py

#################################
updatedb


###################################
# add local user
useradd --user-group --create-home --groups sudo %SHELLUSERNAME%
USERPWD=$(pwgen -1 -c -n -s 16 1)
echo $USERPWD > %PWDOUTPUTDIR%
echo "%SHELLUSERNAME%:$USERPWD" | chpasswd



###################################
# set localhost
echo "127.0.0.1 %COMPUTERNAME%" >> /etc/hosts
echo "127.0.0.1 %HOSTFQDN%" >> /etc/hosts

echo "done"
read foo
'@

$WSLLocalUserInit=@'
ln -s %LOCALPRIVDIR% localdir
mkdir -p ~/python/envs/ansible
cd ~/python/envs
virtualenv ansible
source ansible/bin/activate
cd ansible
pip install ansible boto github2 github3.py pywinrm
#
git clone https://github.com/Winterlabs/shellsettings
cd shellsettings
./merge_settings.sh
'@



    # "Data: %MYDATA%" | _Expand-VariablesInString -VariableMappings @{MYDATA="replaced string"}
    $WSLINitPrivSCriptPath = $PSScriptRoot
    if(-not $WSLINitPrivSCriptPath) {
        $WSLINitPrivSCriptPath = (get-location).path
    }
    $WSLINitPrivSCriptPath = Join-Path -Path $(ConvertTo-LowercasePathQualifier -path $WSLINitPrivSCriptPath) -ChildPath "init_bash.sh"
    $WSLInitPrivScript.Replace("`r`n","`n") | `
        _Expand-VariablesInString -VariableMappings @{ 
            SHELLUSERNAME=$env:USERNAME; 
            PWDOUTPUTDIR=ConvertTo-WSLPath -path $(join-path -path $PrivDir -ChildPath "bash_password.txt");
            COMPUTERNAME=$env:COMPUTERNAME.ToLower();
            HOSTFQDN="$env:COMPUTERNAME.$env:USERDNSDOMAIN".ToLower()
         } | Set-Content -Path $WSLINitPrivSCriptPath -Encoding UTF8

    Write-Warning $WSLINitPrivSCriptPath

    Start-Process -FilePath C:\Windows\System32\bash.exe -ArgumentList "-c `"sh $(ConvertTo-WSLPath -path $(join-path -Path $WSLINitPrivSCriptPath -childPath "init_bash.sh"))`"" -NoNewWinodw -Wait











    ###################################
    # git for windows
    $response = Invoke-WebRequest -Uri "https://api.github.com/repos/git-for-windows/git/releases/latest" -UseBasicParsing
    $releasedata = $response.content | ConvertFrom-Json
    $release = $releasedata.assets | ? { ($_.Name -like 'MinGit*64-bit.zip') -and ($_.Name -notlike '*busybox*')  } | Sort-Object created_at -Descending | select -First 1


    $downloadPath = Join-Path -Path $privdir\_down -ChildPath $release.name
    Invoke-WebRequest -Uri $release.browser_download_url -UseBasicParsing -OutFile $downloadPath
    Unblock-File -Path $downloadPath

    Expand-Archive -Path $privdir\_down\$($release.name) -DestinationPath  $PrivDir\tools\MinGit 
    [environment]::SetEnvironmentVariable("Path",$env:Path+"$privdir\tools\MinGit\cmd",[System.EnvironmentVariableTarget]::Machine)

    #$releasedata.assets | Sort-Object created_at -Descending | select Name, created_at

    




    #############################################
    # nuget
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -force


    #################################################
    # posh-git
    # TODO: install portable git and add to path
    PowershellGet\install-module -Name Posh-git -scope CurrentUser -Force
    import-module posh-git
    Add-PoshGitToProfile -AllHosts











    ########################################################
    # set explorer options
    # https://stackoverflow.com/questions/4491999/configure-windows-explorer-folder-options-through-powershell
    # https://superuser.com/questions/253249/windows-registry-entries-for-default-explorer-view

    $ExplorerRegPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
    $ExplorerRegData = @(
        @{ RegKey = "Hidden"; Value = 1 }
        ,@{ RegKey = "HideFileExt"; Value = 0 }
        ,@{ RegKey = "ShowSuperHidden"; Value = 1 }
        ,@{ RegKey = "HideDrivesWithNoMedia"; Value = 0 }
        ,@{ RegKey = "HideMergeConflicts"; Value = 0 }
        ,@{ RegKey = "AutoCheckSelect"; Value = 0 }
        ,@{ RegKey = "TaskbarAnimations"; Value = 0 }
        ,@{ RegKey = "TaskbarSmallIcons"; Value = 1 }
    )
     
    $ExplorerRegData | ForEach-Object {
        Write-Warning "Setting $($_.RegKey) to $($_.Value)"
        Set-ItemProperty -Path $ExplorerRegPath -Name $_.REgKey -Value $_.Value
    }

    # set desktop
    Set-ItemProperty -Path 'HKCU:\Control Panel\Colors' -Name "Background" -Value "0 0 0"
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name "Wallpaper" -Value ""


    Stop-Process -processname explorer




    #################################################
    # TRackpad turn off right click
    # might need a reboot or re-login
    Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PrecisionTouchPad' -Name RightClickZoneEnabled -Value 0








    ############################################################
    # beyond compare
    Invoke-WebRequest -Uri https://www.scootersoftware.com/BCompare-3.3.13.18981.exe -UseBasicParsing -OutFile $privdir\_down\BCompare-3.3.13.18981.exe
    Unblock-File -Path $privdir\_down\BCompare-3.3.13.18981.exe

    # https://www.scootersoftware.com/vbulletin/showthread.php?15609-Unattended-install
    $BCompSEttingsDir = $PSScriptRoot
    if(-not $BCompSEttingsDir) {
        $BCompSEttingsDir = (Get-Location).Path
    }
    $BCompSettings = Join-Path -Path $BCompSEttingsDir -ChildPath "customizations\bcompare_setup.inf"
    & $privdir\_down\BCompare-3.3.13.18981.exe /silent /loadinf="$BCompSettings"











    ############################
    # vagrant
    # https://www.vagrantup.com/downloads.html

    Invoke-WebRequest -Uri https://releases.hashicorp.com/vagrant/2.0.0/vagrant_2.0.0_x86_64.msi -UseBasicParsing -OutFile $privdir\_down\vagrant_2.0.0_x86_64.msi
    Unblock-File -Path $privdir\_down\vagrant_2.0.0_x86_64.msi

    $package = Get-Package -ProviderName msi -Name "Vagrant" -ErrorAction Continue
    if(-not $package) {
        & msiexec /i $privdir\_down\vagrant_2.0.0_x86_64.msi INSTALLDIR="$privdir\tools\Vagrant" /norestart /passive /log $privdir\install_logs\vagrant.log
    }
    $VagrantPAth = "C:\andreas\local_code\vagrant\.vagrant.d".Replace('\','/')
    [System.Environment]::SetEnvironmentVariable("VAGRANT_HOME",$VagrantPAth,"Machine")
    [System.Environment]::SetEnvironmentVariable("VAGRANT_DEFAULT_PROVIDER","hyperv","Machine")











    ##################################
    # Notepad++
    # https://notepad-plus-plus.org/repository/7.x/7.5.1/npp.7.5.1.bin.x64.zip
    $NppAppDir = Join-Path -Path $env:ProgramFiles -ChildPath "Notepad++"
    Invoke-WebRequest -Uri https://notepad-plus-plus.org/repository/7.x/7.5.1/npp.7.5.1.bin.x64.zip -UseBasicParsing -OutFile $privdir\_down\npp.7.5.1.bin.x64.zip
    Unblock-file -Path $PrivDir\_down\npp.7.5.1.bin.x64.zip
    $DEstPath = $NppAppDir
    Expand-Archive -Path $PrivDir\_down\npp.7.5.1.bin.x64.zip -DestinationPath $DEstPath
    #& c:\windows\system32\regsvr32.exe /s $DEstPath\nppshell_05.dll

    New-ProgramShortcut -TargetPath $(Join-Path -Path $NppAppDir -ChildPath "Notepad++.exe") -IconFileName "N++.lnk"

    # shell integration
    # https://github.com/notepad-plus-plus/notepad-plus-plus/issues/92

    mkdir $(Join-Path -Path $env:APPDATA -ChildPath "Notepad++")

    






    ####################################################
    # OpenVPN
    #
    #Invoke-WebRequest -Uri 'https://swupdate.openvpn.org/community/releases/openvpn-install-2.3.17-I601-x86_64.exe' -UseBasicParsing -OutFile $privdir\_down\openvpn-install-2.3.17-I601-x86_64.exe
    Invoke-WebRequest -Uri 'https://swupdate.openvpn.org/community/releases/openvpn-install-2.4.3-I602.exe' -UseBasicParsing -OutFile $privdir\_down\openvpn-install-2.4.3-I602.exe
    Unblock-File -Path $privdir\_down\openvpn-install-2.4.3-I602.exe

    Import-Certificate -FilePath .\customizations\openssl_tap.pem -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher"


    #https://justcheckingonall.wordpress.com/2013/03/11/command-line-installation-of-openvpn/
    #https://b3it.blogspot.se/2014/06/openvpn-silent-intall-and-kaseya.html

    Start-Process -FilePath "$privdir\_down\openvpn-install-2.4.3-I602.exe" `
        -ArgumentList "/S /SELECT_SHORTCUTS=0 /SELECT_OPENVPN=1 /SELECT_SERVICE=1 /SELECT_TAP=1 /SELECT_OPENVPNGUI=1 /SELECT_ASSOCIATIONS=0 /SELECT_OPENSSL_UTILITIES=0 /SELECT_EASYRSA=0 /SELECT_PATH=1 /SELECT_OPENSSLDLLS=1 /SELECT_LZODLLS=1 /SELECT_PKCS11DLLS=1" `
        -NoNewWindow -Wait

    get-service | ? { $_.Name -like 'OpenVPN*'} | stop-service -PassThru | Set-Service -StartupType Manual








    ######################################################
    # Path Copy Copy
    # https://github.com/clechasseur/pathcopycopy/releases/download/14.0/PathCopyCopy14.0.exe
    #
    Invoke-WebRequest -Uri 'https://github.com/clechasseur/pathcopycopy/releases/download/14.0/PathCopyCopy14.0.exe' -UseBasicParsing -OutFile $privdir\_down\PathCopyCopy14.0.exe
    Unblock-File -Path $privdir\_down\PathCopyCopy14.0.exe






    ###########################################################
    # Greenshot
    # https://github.com/greenshot/greenshot/releases/download/Greenshot-RELEASE-1.2.10.6/Greenshot-INSTALLER-1.2.10.6-RELEASE.exe

    Invoke-WebRequest -Uri 'https://github.com/greenshot/greenshot/releases/download/Greenshot-RELEASE-1.2.10.6/Greenshot-INSTALLER-1.2.10.6-RELEASE.exe' -UseBasicParsing -OutFile $privdir\_down\Greenshot-INSTALLER-1.2.10.6-RELEASE.exe
    Unblock-File -Path "$privdir\_down\Greenshot-INSTALLER-1.2.10.6-RELEASE.exe"

    



    ############################################################
    # Wireshark
    # https://1.eu.dl.wireshark.org/win64/Wireshark-win64-2.4.1.exe

    Invoke-WebRequest -Uri 'https://1.eu.dl.wireshark.org/win64/Wireshark-win64-2.4.1.exe' -UseBasicParsing -OutFile "$privdir\_down\Wireshark-win64-2.4.1.exe"
    Unblock-File -Path "$privdir\_down\Wireshark-win64-2.4.1.exe"



    #############################################################
    # SoapUI
    # http://smartbearsoftware.com/distrib/soapui/5.2.1/SoapUI-x64-5.2.1.exe
    Invoke-WebRequest -Uri 'http://smartbearsoftware.com/distrib/soapui/5.2.1/SoapUI-x64-5.2.1.exe' -UseBasicParsing -OutFile "$privdir\_down\SoapUI-x64-5.2.1.exe"
    Unblock-File -Path "$privdir\_down\SoapUI-x64-5.2.1.exe"

    # https://community.smartbear.com/t5/SoapUI-Open-Source/Silent-Install-Option/td-p/10921
    Start-Process -FilePath "$privdir\_down\SoapUI-x64-5.2.1.exe" -ArgumentList "-q" -NoNewWindow -Wait





    #######################################################
    # MS SQL Management Studio 2016
    # $CorpRepo\Program_Licens\Microsoft en\SQL Server\SQL Server 2016 Enterprise Core 64 bit\Management Studio MS SQL 2016\SSMS-Setup-ENU.exe /?
    Start-Process -FilePath "$CorpRepo\Program_Licens\Microsoft en\SQL Server\SQL Server 2016 Enterprise Core 64 bit\Management Studio MS SQL 2016\SSMS-Setup-ENU.exe" `
        -ArgumentList "/Instal /Quiet /NoRestart" -Wait -NoNewWindow





    #########################################################
    # ConEmu
    # https://conemu.github.io/en/AutoInstall.html
    # powershell -NoProfile -ExecutionPolicy Unrestricted -Command "iex ((new-object net.webclient).DownloadString('https://conemu.github.io/install.ps1'))"

    $ConEmuInstallPath = Join-Path -Path "$privdir\tools" -ChildPath "ConEmu"
    # Directory must be writable to be able to edit settings
    $ConEmuInstallParams = @{
        ver="stable";
        dst=$ConEmuInstallPath;
        lnk=$False;
        xml=‘https://conemu.github.io/ConEmu.xml’;
        run=$False
    }

    $ConEmuInstallCmd = ""

    $ConEmuInstallParams.keys | ForEach-Object {
        $param = $_
        $value = $ConEmuInstallParams.Item($param)
        Write-Warning "$param - $value"
        if($value -is [bool]) {
            $ConEmuInstallCMd += "set $param `$$($value.ToString()); "
        } else {
            $ConEmuInstallCMd += "set $param `'$value`'; "
        }
    }

    Write-Warning "Starting ConEmu install with params: `"$ConEmuInstallCmd`""

    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Unrestricted -Command `"$ConEmuInstallCmd; iex ((new-object net.webclient).DownloadString('https://conemu.github.io/install2.ps1'))`"" -NoNewWindow -Wait
    New-ProgramShortcut -TargetPath $(Join-Path -Path $ConEmuInstallPath -ChildPath "ConEmu64.exe") -IconFileName "ConEmu" -WorkingDirectory $ConEmuInstallPath
    Copy-Item -Path .\customizations\ConEmu.xml -Destination $ConEmuInstallPath -Force








    ###############################################
    # MIsc stuff
    
    # update powershell help
    update-help

    # show "Run as user"
    # https://superuser.com/questions/1045158/how-do-you-run-as-a-different-user-from-the-start-menu-in-windows-10
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name ShowRunasDifferentuserinStart -Value 1 -type DWORD

    Stop-Process -processname explorer


    <#
    Get-WindowsOptionalFeature -Online | select FeatureName | Sort-Object FeatureName | ogv

    Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V


    Get-WindowsPackage

    #>

    <#
    TODO:
        - tackpad
            * turn off right click on trackpad

        - explorer
            * turn on show all files
            * turn on show file extensions
            * consolidate tray icons

        - chrome
            * set download path
            * set language to english
            * pin to taskbar
            * Fix registry to enable incognito mode


    #>
}

$dir = Read-Host -Prompt "Privdir"
$crepo = Read-Host -Prompt "Corp repo"

#Install-WorkClient -PrivDir $dir -CorpRepo $crepo

