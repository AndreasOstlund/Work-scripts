Function Save-FileOnURL() {
    [cmdletBinding()]
    Param(
        [string]$URL
        ,[string]$OutputPath
        ,[string]$Filename
    )

    $FullOutputPath = Join-Path -Path $OutputPath -ChildPath $Filename

    Invoke-WebRequest -Uri $URL -OutFile $FullOutputPath -UseBasicParsing
    Unblock-File -Path $FullOutputPath
}

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

        ,[Parameter(Mandatory=$False
                    ,HelpMessage="if not set, icon will be created on desktop")]
        [string]$IconPath

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

        if(-not $IconPath) {

            if($AllUsers) {
                $IconPath = $ShellObj.SpecialFolders("AllUsersDesktop")
        
            } else {
                $IconPath = Join-Path -Path $env:USERPROFILE -ChildPath "Desktop"
        
            }
        }

        Write-Verbose "Creating desktop icon $IconFileName in $IconPath"

        $ShortCut = $ShellObj.CreateShortcut( $(Join-Path -Path $IconPath -ChildPath $IconFileName) )
        $ShortCut.TargetPath = $TargetPath

        if($WorkingDirectory) {
            $ShortCut.WorkingDirectory = $WorkingDirectory
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
    $subdirs = @("_down","install_logs","scheduled_scripts","tools","local_code","local_code\vagrant","temp","greenshot","VMs\sources","VMs\machines")
    $subdirs | ForEach-Object {
        New-DirectoryIfNotExists -dirname $(Join-Path -Path $privdir -ChildPath $_) 
    }





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

    New-DirectoryIfNotExists -dirname "$privdir\VMs\machines\Hyper-V"
    # Hyper-V icon
    #Copy-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Administrative Tools\Hyper-V Manager.lnk" -Destination "" -Verbose

    # import latest hyper-v module
    get-module -ListAvailable | ? { $_.Name -eq "Hyper-V" } | Sort-Object -Property Version -Descending | select -First 1  | Import-Module -Verbose

    Set-VMHost -VirtualHardDiskPath $privdir\VMs\machines\Hyper-V
    Set-VMHost -VirtualMachinePath $privdir\VMs\machines\Hyper-V

    $ExtNIC = Get-NetAdapter -Name Wi-Fi

    New-VMSwitch -Name switch_private -SwitchType Private
    New-VMSwitch -Name switch_internal -SwitchType Internal
    New-VMSwitch -Name switch_external -NetAdapterName $ExtNIC.Name


    ########################################
    #
    # Microsoft Virtual machine converter
    # 
    # https://www.microsoft.com/en-us/download/details.aspx?id=42497
    # https://download.microsoft.com/download/9/1/E/91E9F42C-3F1F-4AD9-92B7-8DD65DA3B0C2/mvmc_setup.msi
    $DownloadPath = Join-Path -Path $privdir -ChildPath "installrepo"
    Save-FileOnURL -URL "https://download.microsoft.com/download/9/1/E/91E9F42C-3F1F-4AD9-92B7-8DD65DA3B0C2/mvmc_setup.msi" -OutputPath $DownloadPath -Filename "mvmc_setup.msi"

    & msiexec /i $(join-path -Path $DownloadPath -ChildPath "mvmc_setup.msi") /norestart /passive /log $(join-path -Path $privdir -ChildPath "install_logs\mvmc_setup.log")


    ##########################################
    #
    # Vmware VM converter
    #
    # https://my.vmware.com/group/vmware/evalcenter?p=converter

    
    $DownloadPath = Join-Path -Path $privdir -ChildPath "installrepo"

    #

    #https://kb.vmware.com/s/article/1008207?language=en_US

    #VMware-Converter-Agent.exe /s /v"/l*v %TEMP%/vmconvagentmsi.log /qn"

    Start-Process -FilePath $(Join-Path -Path $DownloadPath -ChildPath "VMware-converter-en-6.1.1-3533064.exe") `
        -ArgumentList "/s /v`"/l*v $(join-path -Path $privdir -ChildPath "install_logs\vmware_converter.log") /qn`"" -Wait -NoNewWindow
        


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


    #Chrome policies
    Remove-Item -Path HKCU:\SOFTWARE\Policies\Google -Force -Recurse 
    Set-ItemProperty -path HKLM:\SOFTWARE\Policies\Google\Chrome -name 'IncognitoModeAvailability' -Value 0



    Stop-Process -processname explorer


    <#
    Edge options

    HKEY_CURRENT_USER\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main
"Theme"=dword:00000000
"Default Download Directory"="C:\\Users\\aos019\\Downloads"
"Use FormSuggest"="no"    
"DisallowDefaultBrowserPrompt"=dword:00000000


[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer]
"EnableAutoTray"=dword:00000001
    #>



    <#
    IE options

    HKEY_CURRENT_USER\SOFTWARE\Microsoft\Internet Explorer\Main
    
 "Use FormSuggest"="no"
"FormSuggest Passwords"="no"
"FormSuggest PW Ask"="no"
    
    HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\Main\WindowsSearch
"ConfiguredScopes"=dword:00000000
"AutoCompleteGroups"=dword:00000005
"EnabledScopes"=dword:00000000

"Friendly http errors"="no"
"Start Page"="http://intra.domain.com/"


    #>




    #################################################
    # Trackpad turn off right click
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
    $VagrantPAth = "$privdir\local_code\vagrant\.vagrant.d".Replace('\','/')
    [System.Environment]::SetEnvironmentVariable("VAGRANT_HOME",$VagrantPAth,"Machine")
    [System.Environment]::SetEnvironmentVariable("VAGRANT_DEFAULT_PROVIDER","hyperv","Machine")











    ##################################
    # Notepad++
    #
    # 64 bit. no plugin manager
    # https://notepad-plus-plus.org/repository/7.x/7.5.1/npp.7.5.1.bin.x64.zip
    # https://notepad-plus-plus.org/repository/7.x/7.5.1/npp.7.5.1.bin.zip
    $NppAppDir = Join-Path -Path ${env:ProgramFiles(x86)} -ChildPath "Notepad++"
    $NppURL = "https://notepad-plus-plus.org/repository/7.x/7.5.1/npp.7.5.1.bin.zip"
    #$NppUrl = "https://notepad-plus-plus.org/repository/7.x/7.5.1/npp.7.5.1.bin.x64.zip"
    $DownloadPath = $(Join-Path -Path $privdir -ChildPath "installrepo")

    Save-FileOnURL -URL $NppURL -OutputPath $DownloadPath -Filename "notepad++.zip"

    #Invoke-WebRequest -Uri  -UseBasicParsing -OutFile $privdir\_down\npp.7.5.1.bin.x64.zip
    #Unblock-file -Path $PrivDir\_down\npp.7.5.1.bin.x64.zip

    $DestPath = $NppAppDir
    Expand-Archive -Path $(Join-Path -Path $downloadPath -ChildPath "notepad++.zip" ) -DestinationPath $DEstPath
    #& c:\windows\system32\regsvr32.exe /s $DEstPath\nppshell_05.dll

    New-ProgramShortcut -TargetPath $(Join-Path -Path $NppAppDir -ChildPath "Notepad++.exe") -IconFileName "N++.lnk"
    New-ProgramShortcut -TargetPath $(Join-Path -Path $NppAppDir -ChildPath "Notepad++.exe") -IconFileName "Notepad++.lnk" -IconPath "$env:APPDATA\Microsoft\Windows\Start Menu\Programs"

    
    mkdir $(Join-Path -Path $env:APPDATA -ChildPath "Notepad++")

    # shell integration
    # https://github.com/notepad-plus-plus/notepad-plus-plus/issues/92    
    #https://blogs.msdn.microsoft.com/lior/2009/06/18/what-no-hkcr-in-powershell/
    New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
    New-Item -Path HKCR:\*\Shell\EditWithNpp -Value "Edit with Notepad++"
    New-Item -Path HKCR:\*\Shell\EditWithNpp\command -Value "`"$(Join-Path -Path $NppAppDir -ChildPath "Notepad++.exe")`" `"%1`" `"%*`""


    #Notepad++ plugin manager
    Save-FileOnURL -URL "https://github.com/bruderstein/nppPluginManager/releases/download/v1.4.9/PluginManager_v1.4.9_UNI.zip" -OutputPath $downloadPath -Filename "PluginManager_v1.4.9_UNI.zip"
    Expand-Archive -Path $(Join-Path -Path $downloadPath -ChildPath "PluginManager_v1.4.9_UNI.zip") -DestinationPath $NppAppDir

    #Notepad++ plugins
    # needs to be done after plugin manager has been started
    # or find where source to PLuginManagerPlugins.xml is located and download it and parse it.
    #[xml]$nppPlugindata = Get-Content -Path "$env:APPDATA\Notepad++\plugins\Config\PluginManagerPlugins.xml"
    #
    #$plugin = $nppPlugindata.plugins.plugin | ? { $_.Name -eq 'Tidy2' }
    #$plugin.install.unicode.download

    #XMLTOols
    #Tidy2
    #HTML tag
    #JSON Viewer



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

    $GreenshotConfigDir = $(Join-Path -Path $env:APPDATA -ChildPath "Greenshot")
    if(-not $(Test-Path -Path $GreenshotConfigDir)) { mkdir $GreenshotConfigDir }
    copy -Path .\customizations\Greenshot.ini -Destination $GreenshotConfigDir


    $Package = $(Get-Package -name | ? { $_.Name -like 'Greenshot*'} )

    Invoke-WebRequest -Uri 'https://github.com/greenshot/greenshot/releases/download/Greenshot-RELEASE-1.2.10.6/Greenshot-INSTALLER-1.2.10.6-RELEASE.exe' -UseBasicParsing -OutFile $privdir\_down\Greenshot-INSTALLER-1.2.10.6-RELEASE.exe
    Unblock-File -Path "$privdir\_down\Greenshot-INSTALLER-1.2.10.6-RELEASE.exe"

    



    ############################################################
    # Wireshark
    # https://1.eu.dl.wireshark.org/win64/Wireshark-win64-2.4.1.exe
    $Package = $(Get-Package -name | ? { $_.Name -like 'Wireshark*'} )
    if(-not $Package) {
        Invoke-WebRequest -Uri 'https://1.eu.dl.wireshark.org/win64/Wireshark-win64-2.4.1.exe' -UseBasicParsing -OutFile "$privdir\_down\Wireshark-win64-2.4.1.exe"
        Unblock-File -Path "$privdir\_down\Wireshark-win64-2.4.1.exe"

        # install
    }


    #############################################################
    #
    # SoapUI
    #
    # http://smartbearsoftware.com/distrib/soapui/5.2.1/SoapUI-x64-5.2.1.exe
    Invoke-WebRequest -Uri 'http://smartbearsoftware.com/distrib/soapui/5.2.1/SoapUI-x64-5.2.1.exe' -UseBasicParsing -OutFile "$privdir\_down\SoapUI-x64-5.2.1.exe"
    Unblock-File -Path "$privdir\_down\SoapUI-x64-5.2.1.exe"

    # https://community.smartbear.com/t5/SoapUI-Open-Source/Silent-Install-Option/td-p/10921
    Start-Process -FilePath "$privdir\_down\SoapUI-x64-5.2.1.exe" -ArgumentList "-q" -NoNewWindow -Wait

    # Fix DPI scaling
    # https://stackoverflow.com/questions/36709583/soapui-on-windows-10-high-dpi-4k-scaling-issue
    $value = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide' -Name "PreferExternalManifest" -ErrorAction SilentlyContinue
    if(-not $Value) {
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide' -Name "PreferExternalManifest" -Value 1 -PropertyType DWord
    } else {
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide' -Name "PreferExternalManifest" -Value 1  
    }
  
    $exefile = Get-ChildItem -Path "C:\Program Files\SmartBear\SoapUI-5.2.1\bin\SoapUI*.exe"
    if($exefile) {
        $ManifestFile = "${exefile}.manifest"
    }
    $ManifestContents = @'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0" xmlns:asmv3="urn:schemas-microsoft-com:asm.v3">
    <description>SoapUI</description>
    <trustInfo xmlns="urn:schemas-microsoft-com:asm.v2">
        <security>
            <requestedPrivileges>
                <requestedExecutionLevel xmlns:ms_asmv3="urn:schemas-microsoft-com:asm.v3"
                    level="asInvoker" ms_asmv3:uiAccess="false">
                </requestedExecutionLevel>
            </requestedPrivileges>
        </security>
    </trustInfo>
    <asmv3:application>
        <asmv3:windowsSettings xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">
            <ms_windowsSettings:dpiAware xmlns:ms_windowsSettings="http://schemas.microsoft.com/SMI/2005/WindowsSettings">false</ms_windowsSettings:dpiAware>
        </asmv3:windowsSettings>
    </asmv3:application>
</assembly>    
'@

    $ManifestContents | Set-Content -Path $ManifestFile -Encoding UTF8 -Force






    #######################################################
    # MS SQL Management Studio 2016
    # $CorpRepo\Program_Licens\Microsoft en\SQL Server\SQL Server 2016 Enterprise Core 64 bit\Management Studio MS SQL 2016\SSMS-Setup-ENU.exe /?
    $Package = $(get-package -name "SQL Server 2016 Management Studio" -providername msi)
    if(-not $package) {
        Start-Process -FilePath "$CorpRepo\Program_Licens\Microsoft en\SQL Server\SQL Server 2016 Enterprise Core 64 bit\Management Studio MS SQL 2016\SSMS-Setup-ENU.exe" `
            -ArgumentList "/Instal /Quiet /NoRestart" -Wait -NoNewWindow
    } else {
        Write-Warning "Not installing SQL management studio, it appears installed already."
    }




    #########################################################
    # ConEmu
    # https://conemu.github.io/en/AutoInstall.html
    # powershell -NoProfile -ExecutionPolicy Unrestricted -Command "iex ((new-object net.webclient).DownloadString('https://conemu.github.io/install.ps1'))"

    $ConEmuInstallPath = Join-Path -Path "$privdir\tools" -ChildPath "ConEmu"

    if(-not $(Test-Path -Path $ConEmuInstallPath) ) {

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

    
    }


    ###################################################
    #
    # java
    #
    Start-Process -FilePath"$crepo\Program\java\Windows\jre-8u144-windows-x64.exe" -ArgumentList "AUTO_UPDATE=Disable INSTALL_SILENT=Enable" -NoNewWindow -Wait


    ###################################################
    #
    # GitEye
    #

    Save-FileOnURL -URL "https://downloads-guests.open.collab.net/files/documents/61/13440/GitEye-2.0.0-windows.x86_64.zip" -Filename "GitEye-2.0.0-windows.x86_64.zip" -OutputPath $(Join-Path -Path $privdir -ChildPath "installrepo")

    #GitG
    #Invoke-WebRequest -Uri 'http://ftp.gnome.org/pub/GNOME/binaries/win64/gitg/gitg-x86_64-3.20.0.msi' -UseBasicParsing -OutFile "$privdir\installrepo\gitg-x86_64-3.20.0.msi"
    #Unblock-File -Path "$privdir\installrepo\gitg-x86_64-3.20.0.msi"

    # https://community.smartbear.com/t5/SoapUI-Open-Source/Silent-Install-Option/td-p/10921
    #Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $privdir\installrepo\gitg-x86_64-3.20.0.msi /quiet /passive /log $privdir\install_logs\gitg.log" -NoNewWindow -Wait


    
    ###############################################
    # Visual studio code
    # https://github.com/Microsoft/vscode/archive/1.16.1.zip
    $OutputPath = $(Join-Path -Path $privdir -ChildPath "installrepo")
    Save-FileOnURL -URL "https://go.microsoft.com/fwlink/?Linkid=850641"  -OutputPath $OutputPath -Filename "vSCode_latest.zip"

    Expand-Archive -Path $(Join-Path -Path $OutputPath -ChildPath "vSCode_latest.zip") -DestinationPath $(Join-Path -Path $privdir -ChildPath "tools\VSCode") -Force

    #https://stackoverflow.com/questions/34286515/how-to-install-visual-studio-code-extensions-from-command-line
    #donjayamanne.python
    #ms-vscode.powershell
    #mssql

    # shell integration
    # https://github.com/notepad-plus-plus/notepad-plus-plus/issues/92    
    #https://blogs.msdn.microsoft.com/lior/2009/06/18/what-no-hkcr-in-powershell/
    $psdrive = Get-PSDrive -Name HKCR -ErrorAction SilentlyContinue
    if(-not $psdrive) {
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT    
    }
    New-Item -Path HKCR:\*\Shell\VSCode -Value "Edit with VS Code"
    New-Item -Path HKCR:\*\Shell\VSCode\command -Value "`"$(Join-Path -Path $privdir -ChildPath "tools\VSCode\code.exe")`" `"%1`""
    # new-ItemProperty seems to have trouble with "*"
    # https://powershell.org/forums/topic/cant-set-new-itemproperty-to-registry-path-containing-astrix/
    #New-ItemProperty -Path HKCR:\*\Shell\VSCode -Name Icon -Value "`"$(Join-Path -Path $privdir -ChildPath "tools\VSCode\code.exe")`"" 

    $hive = [Microsoft.Win32.RegistryKey]::OpenBaseKey('ClassesRoot', 'Default')
    #$subKey = $hive.CreateSubKey('*\shell\VSCode', $true)
    $subkey = $hive.OpenSubKey('*\shell\VSCode', $true)
    $subkey.SetValue('Icon', "$(Join-Path -Path $privdir -ChildPath "tools\VSCode\code.exe")", 'String')


    

    ################################################
    #
    # Atom editor
    #
    # https://github.com/atom/atom/releases/download/v1.21.0/atom-x64-windows.zip
    $OutputPath = $(Join-Path -Path $privdir -ChildPath "installrepo")
    Save-FileOnURL -URL "https://github.com/atom/atom/releases/download/v1.21.0/atom-x64-windows.zip"  -OutputPath $OutputPath -Filename "atom-x64-windows.zip"

    $DestinationPath = $(Join-Path -Path $privdir -ChildPath "tools\Atom")
    Expand-Archive -Path $(Join-Path -Path $OutputPath -ChildPath "atom-x64-windows.zip") -DestinationPath $DestinationPath -Force
    if( $(Test-Path -Path $(Join-Path -Path $DestinationPath -ChildPath "Atom x64") ) ) {
        Move-Item -Path $(Join-Path -Path $DestinationPath -ChildPath "Atom x64\*") -Destination $DestinationPath 
    }

    $SettingsDir = Join-Path -Path $DestinationPath -ChildPath "settings"
    mkdir $SettingsDir

    # set config dir
    [environment]::SetEnvironmentVariable("ATOM_HOME",$SettingsDir,[System.EnvironmentVariableTarget]::User)




    ###############################################
    # MIsc stuff
    
    # update powershell help
    update-help

    # show "Run as user"
    # https://superuser.com/questions/1045158/how-do-you-run-as-a-different-user-from-the-start-menu-in-windows-10
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name ShowRunasDifferentuserinStart -Value 1 -type DWORD

    Stop-Process -processname explorer



    #############################################
    #
    # VM sources
    #

    #https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2016
    #http://care.dlservice.microsoft.com/dl/download/1/4/9/149D5452-9B29-4274-B6B3-5361DBDA30BC/14393.0.161119-1705.RS1_REFRESH_SERVER_EVAL_X64FRE_EN-US.ISO
    #http://care.dlservice.microsoft.com/dl/download/6/2/A/62A76ABB-9990-4EFC-A4FE-C7D698DAEB96/9600.17050.WINBLUE_REFRESH.140317-1640_X64FRE_SERVER_EVAL_EN-US-IR3_SSS_X64FREE_EN-US_DV9.ISO
    #
    #http://mirror.nsc.liu.se/CentOS/7/isos/x86_64/CentOS-7-x86_64-Minimal-1708.iso
    #http://mirror.nsc.liu.se/CentOS/7/isos/x86_64/CentOS-7-x86_64-Everything-1708.iso
    #
    #https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise
    #

    $VMSources = @(
        @{ Name="Win2012R2";
           URL="http://care.dlservice.microsoft.com/dl/download/6/2/A/62A76ABB-9990-4EFC-A4FE-C7D698DAEB96/9600.17050.WINBLUE_REFRESH.140317-1640_X64FRE_SERVER_EVAL_EN-US-IR3_SSS_X64FREE_EN-US_DV9.ISO";
           FileName="9600.17050.WINBLUE_REFRESH.140317-1640_X64FRE_SERVER_EVAL_EN-US-IR3_SSS_X64FREE_EN-US_DV9.ISO"
         }
        ,@{
         Name="Win2016"
         URL="http://care.dlservice.microsoft.com/dl/download/1/4/9/149D5452-9B29-4274-B6B3-5361DBDA30BC/14393.0.161119-1705.RS1_REFRESH_SERVER_EVAL_X64FRE_EN-US.ISO"
         FileName="149D5452-9B29-4274-B6B3-5361DBDA30BC/14393.0.161119-1705.RS1_REFRESH_SERVER_EVAL_X64FRE_EN-US.ISO"
        }
        ,@{
         Name="CentOS7Minimal"
         URL="http://mirror.nsc.liu.se/CentOS/7/isos/x86_64/CentOS-7-x86_64-Minimal-1708.iso";
         FileName="CentOS-7-x86_64-Minimal-1708.iso"
        }
        ,@{
          Name="CentOS7Everything"
          URL="http://mirror.nsc.liu.se/CentOS/7/isos/x86_64/CentOS-7-x86_64-Everything-1708.iso"
          FileName="CentOS-7-x86_64-Everything-1708.iso"
        }
    )

    $OutputPath = Join-Path -Path $privdir -ChildPath "VMs\sources"
    $VMSources | ? { $_.Name -like 'CentOS*' } | ForEach-Object {
        Save-FileOnURL -URL $_.URL -OutputPath $OutputPath -Filename $_.FileName -Verbose
    }


    #############################################
    #
    # Printers
    # in private script
    #
    # https://superuser.com/questions/135061/how-to-configure-a-network-printer-using-command-prompt-under-windows-7
    #
    #



    #############################################
    #
    # AnyConnect
    # In private script
    #


    ##############################################
    #
    # VMWare VShpere, powercli
    #
    # http://vsphereclient.vmware.com/vsphereclient/VMware-viclient-all-6.0.0.exe
    # https://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=1019862
    $OutputPath = Join-path -Path $privdir -ChildPath "InstallRepo"
    Save-FileOnURL -URL "http://vsphereclient.vmware.com/vsphereclient/VMware-viclient-all-6.0.0.exe" -OutputPath $OutputPath -Filename "VMware-viclient-all-6.0.0.exe" 
    # /v specifies params to msiexec.
    Start-Process -FilePath $(Join-Path -Path $OutputPath -ChildPath "VMware-viclient-all-6.0.0.exe") `
        -ArgumentList "/s /v`"/qn REBOOT=Reallysuppress /l $(Join-Path -Path $privdir -ChildPath "install_logs\viclient.log")`""  `
         -NoNewWindow -Wait 


    # powercli
    # https://www.powershellgallery.com/packages/VMware.PowerCLI/6.5.3.6870460
    Save-Module -Name VMware.PowerCLI -Path $(join-path -Path $privdir -ChildPath "Installrepo")







    <#
    Get-WindowsOptionalFeature -Online | select FeatureName | Sort-Object FeatureName | ogv

    Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V


    Get-WindowsPackage

    #>

    <#
    TODO:
        - Citrix receiver
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

