Function Save-FileOnURL() {
    [cmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$URL
        ,[Parameter(Mandatory=$True)]
        [string]$OutputPath
        ,[Parameter(Mandatory=$False)]
        [string]$Filename
    )

    if(-not $Filename) {
        # Get the last segment
        $Filename=([System.uri]$URL).Segments[-1]
    }
    $FullOutputPath = Join-Path -Path $OutputPath -ChildPath $Filename

    Invoke-WebRequest -Uri $URL -OutFile $FullOutputPath -UseBasicParsing
    Unblock-File -Path $FullOutputPath

    return $FullOutputPath
}

# https://stackoverflow.com/questions/30189997/how-to-add-attribute-if-it-doesnt-exist-using-powershell
function Add-XMLAttribute([System.Xml.XmlNode] $Node, $Name, $Value) {
  $attrib = $Node.OwnerDocument.CreateAttribute($Name)
  $attrib.Value = $Value
  $node.Attributes.Append($attrib)
}


Function New-DirectoryIfNotExists($dirname) {

    if(-not $(Test-Path -Path $dirname)) { mkdir $dirname }
}

Function Add-CompatibilitySettings {
    Param(
        [Parameter(Mandatory=$True)]
        [string]$ProgramPath,

        [Parameter(Mandatory=$True)]
        [string[]]$CompatModes
    )

    foreach($mode in $CompatModes) {

        switch($mode) {
            "RUNASADMIN" { $compatstr += " $mode" }
            "HIGHDPIAWARE" { $compatstr += " $mode" }
        }
    }

    if($compatstr) {
        $RegPath = "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"
        if(-Not $(Test-path -Path $RegPath) ) { New-Item -Path $RegPath -Name "" }
        New-ItemProperty -Path $RegPath -Name $ProgramPath -Value $compatstr
    }
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

        # TODO: Handle if desktop folder in profile dir is stored on one-drive. In that case saving to c:\users\<users>\Desktop does not work

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

Function Add-ProgramToRegistryAutorun($ProgramName, $exepath) {


    if(-Not $(Test-Path -Path $exepath ) ) {
        Throw "$exepath not found!"
    }

    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name $ProgramName -Value $exepath -PropertyType "String"
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

Function ConvertTo-CygwinPath($Path) {

    $cygpath = ConvertTo-LowercasePathQualifier -path $Path

    return ("/cygdrive/"+$cygpath).Replace(':','').Replace('\','/')
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


Function Get-GitHubProjectLatestRelease {
    [cmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$Project

        ,[Parameter(Mandatory=$True)]
        [string]$FileNameMatch

        ,[Parameter(Mandatory=$False)]
        [string]$ReturnProperty
    )

    $response = Invoke-WebRequest -Uri "https://api.github.com/repos/$Project/releases/latest" -UseBasicParsing
    $releasedata = $response.content | ConvertFrom-Json
    $release = $releasedata.assets | ? { ($_.Name -like $FileNameMatch) } | Sort-Object created_at -Descending | select -First 1

    if($ReturnProperty) {
        return $release.$ReturnProperty
    } else {

        return $release
    }
}


Function _Disable-CertificateVerification() {

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

}


Function Invoke-MSIFile {
    [cmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        $InstallFile

        ,[Parameter(Mandatory=$False)]
        $MSIParameters

        ,[Parameter(Mandatory=$False)]
        $LogDirectory
    )

    if($LogDirectory) {
        $InstallFileName=Split-Path -Path $InstallFile -Leaf
        $LogFile = join-path -path $LogDirectory -ChildPath $("{}_{}.log" -f (Split-Path -Path $InstallFile -Leaf), (get-date -Format "yyyyMMdd-HHmmss"))
        $MSIParameters=$MSIParameters+" /log $LogFile"
    }

    & msiexec /i $InstallFile $MSIParameters

}


Function Install-WorkClient {
    [cmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$PrivDir
        ,[Parameter(Mandatory=$True)]
        [string]$CorpRepo
        ,[Parameter()]
        [switch]$ReplaceTaskManager
    )

    $RebootIt = $False



    _Disable-CertificateVerification



    ############################################
    #
    # Create Directories
    #
    New-DirectoryIfNotExists -dirname $privdir
    $subdirs = @(
        "_down"
        ,"install_logs"
        ,"installrepo"
        ,"scheduled_scripts"
        ,"tools"
        ,"local_code"
        ,"local_code\vagrant"
        ,"temp"
        ,"greenshot"
        ,"VMs\sources"
        ,"VMs\machines"
        )
    $subdirs | ForEach-Object {
        New-DirectoryIfNotExists -dirname $(Join-Path -Path $privdir -ChildPath $_)
    }

    ############################################
    #
    # Global inits
    #
    $InstallRepoPath = Join-Path $privdir -ChildPath "installrepo"
    $HomePath =  $(Join-Path -Path $env:HOMEDRIVE -ChildPath $env:HOMEPATH)
    $ToolsPath = Join-Path -Path $privdir -ChildPath "tools"
    $InstallLogPath = Join-Path -Path $PrivDir -ChildPath "install_logs"

    if(-not $env:AO_HOME) {
        [environment]::SetEnvironmentVariable("AO_HOME",$privdir,[System.EnvironmentVariableTarget]::Machine)
    }


    ############################################
    #
    # Bootstrap
    #
    $OutputFileName = "workscripts.zip"
    Save-FileOnURL -URL https://codeload.github.com/AndreasOstlund/Work-scripts/zip/master -OutputPath $InstallrepoPath -Filename $OutputFileName
    Expand-Archive -Path $(Join-Path -Path $InstallrepoPath -ChildPath $OutputFileName) -DestinationPath $(Join-Path -Path $privdir -ChildPath "local_code")
    Move-Item -Path $(join-path -path $InstallrepoPath  -ChildPath "local_code\work-scripts-master") -Destination   $(join-path -path $InstallrepoPath  -ChildPath "work-scripts")



    #################################################
    # Windows features
    <#
        @{
            FeatureName="Microsoft-Hyper-V"
            All = $TRue
        },
    #>
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



    ############################################
    #
    # Hyper-V config
    #

    # turn Hyper-V off
    bcdedit /set hypervisorlaunchtype off

    # turn it on
    #bcdedit /set hypervisorlaunchtype auto

    # stop service
    get-service vmms | stop-service -PassThru | Set-Service -StartupType Manual


    <#
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
    #>


    ########################################
    #
    # Amazon WorkSpaces
    #
    $DownloadURL = "https://d2td7dqidlhjx7.cloudfront.net/prod/global/windows/Amazon+WorkSpaces.msi"
    $OutputFile = Save-FileOnURL -URL $DownloadURL -OutputPath $InstallrepoPath

    Invoke-MSIFile -InstallFile $OutputFile


    ########################################
    #
    # AWS CLI for windows
    #
    $DownloadedFile = Save-FileOnURL -URL "https://s3.amazonaws.com/aws-cli/AWSCLI64PY3.msi" -OutputPath $InstallrepoPath

    ########################################
    #
    # Amazon WorkDocs sync client
    #
    #$DownloadURL = "https://d28gdqadgmua23.cloudfront.net/win/AmazonWorkDocsSetup.exe"
    $DownloadURL="https://d3f2hupz96ggz3.cloudfront.net/win/AWSWorkDocsDriveClient.msi"
    $InstallFilePath = Save-FileOnURL -URL $DownloadURL -OutputPath $InstallrepoPath #-Filename "AmazonWorkDocsSetup.exe"


    #& msiexec /i $InstallFilePath /norestart /passive /log
    Invoke-MSIFile -InstallFile $InstallFilePath -MSIParameters "/norestart /passive" -Log


    ########################################
    #
    # Microsoft Virtual machine converter
    #
    # https://www.microsoft.com/en-us/download/details.aspx?id=42497
    # https://download.microsoft.com/download/9/1/E/91E9F42C-3F1F-4AD9-92B7-8DD65DA3B0C2/mvmc_setup.msi
    $DownloadURL = "https://download.microsoft.com/download/9/1/E/91E9F42C-3F1F-4AD9-92B7-8DD65DA3B0C2/mvmc_setup.msi"
    $OutputPath = Save-FileOnURL -URL $DownloadURL -OutputPath $InstallRepoPath
    Invoke-MSIFile -InstallFile $OutputPath -MSIParameters "/norestart /passive" -LogDirectory $InstallLogPath
    #& msiexec /i $(join-path -Path $DownloadPath -ChildPath "mvmc_setup.msi")  /log $(join-path -Path $privdir -ChildPath "install_logs\mvmc_setup.log")


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
    #
    # Chrome
    # https://www.google.com/chrome/eula.html?standalone=1&platform=win64
    #
    # These seems to be pretty static... https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7B8B854673-0000-CA19-42BA-9DB366EDCA51%7D%26lang%3Den%26browser%3D4%26usagestats%3D0%26appname%3DGoogle%2520Chrome%26needsadmin%3Dprefers%26ap%3Dx64-stable-statsdef_1/chrome/install/ChromeStandaloneSetup64.exe
    #
    $package = Get-Package -ProviderName msi -Name "Google Chrome" -ErrorAction Continue
    if(-not $package) {
        $DownloadURL = "https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7B030924C0-2C46-0A43-C343-8E1DFA8DF0EB%7D%26lang%3Den%26browser%3D3%26usagestats%3D0%26appname%3DGoogle%2520Chrome%26needsadmin%3Dtrue%26ap%3Dx64-stable-statsdef_1%26brand%3DGCEA/dl/chrome/install/googlechromestandaloneenterprise64.msi"
        $OutputFile = Save-FileOnURL -URL $DownloadURL -OutputPath $InstallRepoPath
        Invoke-MSIFile -InstallFile $OutputFile -MSIParameters "/passive" -LogDirectory $InstallLogPath
        #& msiexec /i $privdir\_down\googlechromestandaloneenterprise64.msi /passive /log $privdir\install_logs\chrome_install.log
    }



    ######################################
    #
    # Firefox
    #
    #https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US
    # https://developer.mozilla.org/en-US/docs/Mozilla/Command_Line_Options
    $DownloadedFile = Save-FileOnURL -URL "https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US" -OutputPath $InstallRepoPath -Filename "firefox.exe"
    # STart installation as silent (-ms)
    Start-Process -FilePath $DownloadedFile -ArgumentList "-ms" -Wait -NoNewWindow


    $profilepath = $(Join-Path -Path $privdir -ChildPath "ff_profile")
    New-DirectoryIfNotExists -dirname $profilepath
    $FFSettingsPath = $(Join-Path -Path $env:APPDATA -ChildPath "Mozilla\Firefox\")
    $FFProfileINIPath = $(Join-Path -Path $FFSettingsPath -ChildPath "profiles.ini")


    [xml]$FFInstallData = get-package | ? { $_.Name -like 'Mozilla firefox*' } | select -ExpandProperty SwidTagText

    $FFExePath = join-path -path $FFInstallData.SoftwareIdentity.meta.InstallLocation -ChildPath "firefox.exe"
    if($(Test-Path -Path $FFExePath)) {

        Start-Process -FilePath $FFExePath -ArgumentList "-CreateProfile `"ao_profile $profilepath`"" -Wait

    } else {
        Write-Warning "Could not find Firefox installed on path: $FFExePath"
    }

    $FFChromePath = $(Join-Path -Path $profilepath -ChildPath "chrome")
    New-DirectoryIfNotExists -dirname $FFChromePath
    "" | set-content -Path $(join-path -path $FFChromePath -ChildPath "userChrome.css")




    ########################################################
    # RSAT for windows 10. KB2693643
    # https://download.microsoft.com/download/1/D/8/1D8B5022-5477-4B9A-8104-6A71FF9D98AB/WindowsTH-RSAT_WS2016-x64.msu
    Save-FileOnURL -URL "https://download.microsoft.com/download/1/D/8/1D8B5022-5477-4B9A-8104-6A71FF9D98AB/WindowsTH-RSAT_WS2016-x64.msu" -OutputPath $InstallRepoPath -Filename "windows10_rsat.msu"
    $rsat = get-hotfix -Id KB2693643
    if(-not $rsat) {
        Start-Process -FilePath C:\Windows\System32\wusa.exe -ArgumentList "$(join-path -path $InstallRepoPath -ChildPath "windows10_rsat.msu") /quiet /norestart /log:$privdir\install_logs\rsat_install.log" -WindowStyle Hidden -Wait
        $RebootIt = $true
    }









    ###################################
    #
    # Create login script
    #
$LoginSCript=@'
Get-process Driftinformation | stop-process
Remove-Item -Path HKCU:\SOFTWARE\Policies\Google -Force -Recurse
Remove-Item -Path HKLM:\SOFTWARE\Policies\Google -Force -Recurse
Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name "Driftinfo"
'@



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
    #
    # Sysinternals
    #
    #$SysinternalsAppDir = join-path -path $env:ProgramFiles -ChildPath "sysinternals"
    $SysinternalsAppDir = join-path -path $ToolsPath -ChildPath "sysinternals"
    $OutputFile = Save-FileOnURL -URL "https://download.sysinternals.com/files/SysinternalsSuite.zip" -OutputPath $InstallRepoPath
    remove-Item -Path $SysinternalsAppDir -Force
    mkdir $SysinternalsAppDir
    Expand-Archive -Path $OutputFile -DestinationPath $SysinternalsAppDir -Force

    & reg import .\customizations\sysinternals.reg

    & "$($SysinternalsAppDir)\procexp.exe" -accepteula

    New-ProgramShortcut -TargetPath $(Join-Path -Path $SysinternalsAppDir -ChildPath "procexp.exe") -IconFileName "Sysinternals ProcessExplorer"
    Add-CompatibilitySettings -ProgramPath $(Join-Path -Path $SysinternalsAppDir -ChildPath "procexp.exe")  -CompatModes "RUNASADMIN"

    if($ReplaceTaskManager) {

        # Change task manager to process explorer
        $sysinternals_replace_taskmanager_regpath="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe"
        if(Test-Path $sysinternals_replace_taskmanager_regpath) {

            try {
                $TaskManagerDebugger = Get-ItemProperty -Path $sysinternals_replace_taskmanager_regpath -Name "Debugger"

                # use join-path here to be compatible with other platforms
                if( $($TaskManagerDebugger.Debugger) -ne $(Join-Path -Path $SysinternalsAppDir -ChildPath "procexp.exe") ) {
                    New-ItemProperty -Path $sysinternals_replace_taskmanager_regpath -Name "Debugger" -Value "$SysinternalsAppDir\procexp.exe" -PropertyType String -Force | Out-Null
                }
            }
            catch {
                Write-Warning "Could replace task manager. $($_.Exception.Message)"
            }
        }
        else
        {
            # Create reg path if it does not exist.
            New-Item -Path $sysinternals_replace_taskmanager_regpath -Force | Out-Null
            New-ItemProperty -Path $sysinternals_replace_taskmanager_regpath -Name "Debugger" -Value $(Join-Path -Path $SysinternalsAppDir -ChildPath "procexp.exe")  -PropertyType String -Force
        }
    }





    #########################################
    # Linux Subsystem for Windows
    #
    #
    $Features = @(
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

    # enable developer mode for lInux subsystem
    New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock -Name AllowDevelopmentWithoutDevLicense -PropertyType DWord -Value 1 -Force

    # https://damsteen.nl/blog/2018/08/29/installing-wsl-manually-on-non-system-drive
    $OutputPath = Save-FileOnURL -URL https://aka.ms/wsl-ubuntu-1804 -OutputPath $InstallRepoPath -Filename "Ubuntu1804.zip"
    $InstallPath = $(Join-Path -Path $ToolsPath -ChildPath "WSL\Ubuntu-1804")
    mkdir $InstallPath

    Expand-Archive -Path $OutputPath -DestinationPath $InstallPath

    $InstallFile = Join-Path -Path $InstallPath -ChildPath "ubuntu1804.exe"
    Start-Process -FilePath 'c:\windows\system32\cmd.exe' -ArgumentList @('/c',$InstallFile,'install','--root') -NoNewWindow -Wait `
            -WorkingDirectory $InstallPath `
            -RedirectStandardError $(Join-Path -Path $InstallLogPath -ChildPath "WSL_Ubuntu1804_stderr.log") `
            -RedirectStandardOutput $(join-path -Path $InstallLogPath -ChildPath "WSL_Ubuntu1804_stdout.log")

    # lxrun not valid in 1803
    #Start-Process -FilePath C:\Windows\System32\cmd.exe -ArgumentList "/c `"lxrun /install /y`"" -NoNewWindow -Wait
    # initially set default user as root
    #Start-Process -FilePath C:\Windows\System32\cmd.exe -ArgumentList "/c `"lxrun /setdefaultuser root /y`"" -NoNewWindow -Wait



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
apt-get update
apt-get upgrade
apt-get --assume-yes install vim git tmux python-pip python-dev libffi-dev libssl-dev pwgen python-virtualenv jq

#pip install ansible
#boto is needed by ec2 module
#pip install boto
# github3.py needed by github_release module
#pip install github2 github3.py

pip install --user virtualenvwrapper pipenv aws

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

echo 'EXTRA_OPTS="-L 15"' >> /etc/default/cron


echo "done"
read foo
'@

$WSLLocalUserInit=@'
ln -s %LOCALPRIVDIR% localdir


cat <<'EOF' >>~/.bashrc
settitle() {
    title=$1
    [ -z "$title" ] && title="bash"
    printf "\033k$title\033\\"
}

gitbranch() {
    [ -z $1 ] && git branch -vv -a || git branch -vv -a | grep -i $1
}
settitle () {
    title=$1;
    [ -z "$title" ] && title="bash";
    printf "\033k$title\033\\"
}


if [ -f "${HOME}/.bash_aliases" ]; then
  source "${HOME}/.bash_aliases"
fi

# handle ssh-agent
if [ ! -e ~/.ssh_agent_env ]; then
  echo ".ssh_agent_env not found. executing ssh-agent..."
  ssh-agent 1>~/.ssh_agent_env
  eval `cat ~/.ssh_agent_env`
  ssh-add
else
  echo ".ssh_agent_env found. reading env file..."
  eval `cat ~/.ssh_agent_env`
  ps -p $SSH_AGENT_PID | grep -q "ssh-agent"
  status=$?
  if [ $status -gt 0 ]; then
    echo "ssh-agent pid in .ssh_agent_env looks stale. re-executing..."
    ssh-agent 1>~/.ssh_agent_env
    eval `cat ~/.ssh_agent_env`
    ssh-add
  else
    echo "found an ssh-agent with pid $SSH_AGENT_PID"
  fi
fi


# run stuff when executed from TMUX
if [[ $TMUX ]]; then
    cd ~/local/
fi

export WORKON_HOME=$HOME/.virtualenvs
export PIP_VIRTUALENV_BASE=$WORKON_HOME
source /usr/bin/virtualenvwrapper.sh

export PATH=$PATH:~/.local/bin
export USERNAME=$USER # for old cygwin scripts


export HISTSIZE=5000
export HISTFILESIZE=$HISTSIZE
export HISTTIMEFORMAT="%Y-%m-%d %H:%M:%S %s "
shopt -s histappend
EOF

source /usr/bin/virtualenvwrapper.sh

mkvirtualenv awspy2dev
pip install boto3 requests pylint


#mkdir -p ~/python/envs/ansible
#cd ~/python/envs
#virtualenv ansible
#source ansible/bin/activate
#cd ansible
#pip install ansible boto github2 github3.py pywinrm
##
#git clone https://github.com/Winterlabs/shellsettings
#cd shellsettings
#./merge_settings.sh
'@



    # "Data: %MYDATA%" | _Expand-VariablesInString -VariableMappings @{MYDATA="replaced string"}
    $WSLINitPrivSCriptPath = $PSScriptRoot
    if(-not $WSLINitPrivSCriptPath) {
        $WSLINitPrivSCriptPath = (get-location).path
    }
    $WSLINitPrivSCriptPath = Join-Path -Path $(ConvertTo-LowercasePathQualifier -path $WSLINitPrivSCriptPath) -ChildPath "init_wsl.sh"
    $WSLInitPrivScript.Replace("`r`n","`n") | `
        _Expand-VariablesInString -VariableMappings @{
            SHELLUSERNAME=$env:USERNAME;
            PWDOUTPUTDIR=ConvertTo-WSLPath -path $(join-path -path $PrivDir -ChildPath "bash_password.txt");
            COMPUTERNAME=$env:COMPUTERNAME.ToLower();
            HOSTFQDN="$env:COMPUTERNAME.$env:USERDNSDOMAIN".ToLower()
         } | Set-Content -Path $WSLINitPrivSCriptPath -Encoding Ascii

    Write-Warning $WSLINitPrivSCriptPath

    Start-Process -FilePath C:\Windows\System32\bash.exe -ArgumentList "-c `"sh $(ConvertTo-WSLPath -path $WSLINitPrivSCriptPath)`"" -Wait


    & C:\Windows\System32\bash.exe -c "sh -x $(ConvertTo-WSLPath -path $WSLINitPrivSCriptPath)"


    ###################################
    #
    # AltDrag
    #
    $reldata = Get-GitHubProjectLatestRelease -Project "stefansundin/altdrag"  -FileNameMatch 'AltDrag*.exe'
    if($reldata.browser_download_url) {
        $OutputFile = Save-FileOnURL -URL $reldata.browser_download_url -OutputPath $InstallRepoPath

        # Install
        & $OutputFile

        #TODO: Silent install
        # installs in profile dir
        $DestinationPath = Join-Path -Path $env:APPDATA -ChildPath "AltDrag"
        $ExePath = Join-Path -Path $DestinationPath -ChildPath "altdrag.exe"
        if($(Test-Path -Path $ExePath)) {
            Add-CompatibilitySettings -ProgramPath $ExePath -CompatModes "HIGHDPIAWARE"
        }
    } else {
        Write-Warning "Could not get URL for AltDrag"
    }




    #############################################
    # nuget
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -force
    #Install-PackageProvider -Name NuGet -force


    #################################################
    # posh-git
    # TODO: install portable git and add to path
    PowershellGet\install-module -Name Posh-git -scope CurrentUser -Force
    import-module posh-git
    Add-PoshGitToProfile -AllHosts


    #################################################
    #
    # Powershell ISE Solarized theme
    #
    $DownloadURL = "https://codeload.github.com/rakheshster/Solarize-PSISE/zip/master"
    $DestinationPath = Join-Path -Path $ToolsPath -ChildPath "Solarize-PSISE"
    Save-FileOnURL -URL $DownloadURL -OutputPath $InstallrepoPath -Filename "Solarize-PSISE-master.zip"
    Expand-Archive -Path $(Join-Path -Path $InstallrepoPath -ChildPath "Solarize-PSISE-master.zip") -DestinationPath $ToolsPath
    Move-Item -Path $(Join-Path -Path $ToolsPath -ChildPath "Solarize-PSISE-master") -Destination $DestinationPath


    # create a profile if no exist
    if(!(Test-Path $profile)) { New-Item -ItemType File -Path $profile -Force }
$ProfileScript=@"
if(`$(`$host.name) -eq 'Windows PowerShell ISE Host') {
    $(Join-Path -Path $DestinationPath -ChildPath "Solarize-PSISE-AddOnMenu.ps1")  -Apply -Dark
}
"@

    $ProfileScript | Add-Content -Path $profile


    #################################################
    #
    # Powershell Console Solarized theme
    #
    $InstallPath=Join-Path -Path $ToolsPath -ChildPath "cmd-colors-solarized"
    Save-FileOnURL -URL "https://codeload.github.com/neilpa/cmd-colors-solarized/zip/master" -OutputPath $InstallrepoPath -Filename "cmd-colors-solarized.zip"
    Expand-Archive -Path $(join-path -Path $InstallrepoPath -ChildPath "cmd-colors-solarized.zip") -DestinationPath $ToolsPath -Verbose
    Move-item -Path $(Join-Path -Path $ToolsPath -ChildPath "cmd-colors-solarized-master") -Destination $InstallPath

    @("$($env:APPDATA)\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell.lnk"
     ,"$($env:APPDATA)\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Windows PowerShell.lnk"
     ) | ForEach-Object {
        if( $(Test-Path -Path $_) ) {
            & $(Join-Path -Path $InstallPath -ChildPath "Update-Link.ps1") $_ dark
        }
    }

    @'
if(-Not `$ENV:WT_SESSION) {
. (Join-Path -Path (Split-Path -Parent -Path $PROFILE) -ChildPath $(switch($HOST.UI.RawUI.BackgroundColor.ToString()){'White'{'Set-SolarizedLightColorDefaults.ps1'}'Black'{'Set-SolarizedDarkColorDefaults.ps1'}default{return}}))
} else {
   set-theme aostlund
}
'@ | Add-Content -Path "$($env:HOME)\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"



@'
if($GitPromptSettings) {
    $GitPromptSettings.DefaultPromptPrefix = '$(Get-Date -f "yyyy-MM-dd HH:mm:ss") '
} else {
    function prompt() { '$(Get-Date -f "yyyy-MM-dd HH:mm:ss") '+"PS $($executionContext.SessionState.Path.CurrentLocation)$('>' * ($nestedPromptLevel + 1)) "; }
}
'@ | Add-Content -Path $profile.CurrentUserAllHosts


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
        ,@{ RegKey = "DisallowShaking"; Value = 1 }
        ,@{ RegKey = "DisablePreviewDesktop"; Value = 0 }
    )

    $ExplorerRegData | ForEach-Object {
        Write-Warning "Setting $($_.RegKey) to $($_.Value)"
        Set-ItemProperty -Path $ExplorerRegPath -Name $_.REgKey -Value $_.Value
    }

    # set desktop color and wallpaper
    Set-ItemProperty -Path 'HKCU:\Control Panel\Colors' -Name "Background" -Value "0 0 0"
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name "Wallpaper" -Value ""


    #Chrome policies
    Remove-Item -Path HKCU:\SOFTWARE\Policies\Google -Force -Recurse
    Set-ItemProperty -path HKLM:\SOFTWARE\Policies\Google\Chrome -name 'IncognitoModeAvailability' -Value 0

    # show "Run as user"
    # https://superuser.com/questions/1045158/how-do-you-run-as-a-different-user-from-the-start-menu-in-windows-10
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name ShowRunasDifferentuserinStart -Value 1 -type DWORD

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
    #
    # Unpin crap from taskbar
    #
    # %LOCALAPPDATA%\Microsoft\Windows\Shell\LayoutModification.xml

    #################################################
    #
    # Outlook settngs
    #

    # https://support.microsoft.com/en-us/help/829982/-outlook-blocked-access-to-the-following-potentially-unsafe-attachment
    New-ItemProperty -Path HKCU:\Software\Microsoft\Office\16.0\Outlook\security -Name Level1Remove -Value ".cer"



    #################################################
    # Trackpad turn off right click
    # might need a reboot or re-login
    Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PrecisionTouchPad' -Name RightClickZoneEnabled -Value 0








    ############################################################
    #
    # beyond compare
    #
    $RequestBody=@{zz="dl4"; platform="win"}
    $BCompareVersion = Invoke-WebRequest -Uri "https://www.scootersoftware.com/download.php" -UseBasicParsing -Method Post -Body $RequestBody  | select -ExpandProperty Links | ? { $_.href -match 'BCompare-[0-9].*' }
    # by filtering on BCompare-[0-9] we should only get one version, the english one.
    # but use [0] just in case...
    $DownloadURL = "https://www.scootersoftware.com"+$BCompareVersion[0].href
    Write-Warning ("Downloading $DownloadURL")
    $Outputfile = Save-FileOnURL -URL $DownloadURL -OutputPath $InstallRepoPath

    $DestinationPath = join-path -path $ToolsPath -childpath  "BC4"

    # https://www.scootersoftware.com/vbulletin/showthread.php?15609-Unattended-install
    $BCompSEttingsDir = $PSScriptRoot
    if(-not $BCompSEttingsDir) {
        $BCompSEttingsDir = (Get-Location).Path
    }
    $BCompSettings = Join-Path -Path $BCompSEttingsDir -ChildPath "customizations\bcompare_setup.inf"
    # Start setup
    # C:\Program Files (x86)\Beyond Compare 3
    & $OutputFile /silent /loadinf="$BCompSettings"


    $ExePath = Join-Path -Path $DestinationPath -ChildPath "BCompare.exe"

    # Add icon to start menu
    # TODO: look up in registry where profile programs folder is located...
    New-ProgramShortcut -TargetPath $ExePath `
                        -WorkingDirectory $DestinationPath `
                        -IconPath "$($env:APPDATA)\Microsoft\Windows\Start Menu\Programs\" -IconFileName "Beyond Compare"





    ############################
    #
    # vagrant
    #
    # https://www.vagrantup.com/downloads.html

    # get releases directory listing
    $ReleaseURL = "https://releases.hashicorp.com"
    # -UseBasicParsing is not used here to get more info on the links property
    $data = Invoke-WebRequest -Uri "$ReleaseURL/vagrant" -DisableKeepAlive
    # try and get the latest release
    $release = $data.links | Sort-Object -Property outerText -Descending | select -first 1

    $data = Invoke-WebRequest -Uri "$ReleaseURL$($release.outerText)" -DisableKeepAlive

    $WinRelease = $data.Links | ? { $_.href -like '*_64.msi'} | select -first 1

    <#
    $WinRelease should now be like

innerHTML    : vagrant_2.0.4_x86_64.msi
innerText    : vagrant_2.0.4_x86_64.msi
outerHTML    : <A href="/vagrant/2.0.4/vagrant_2.0.4_x86_64.msi" data-arch="x86_64" data-os="windows" data-version="2.0.4" data-product="vagrant">vagrant_2.0.4_x86_64.msi</A>
outerText    : vagrant_2.0.4_x86_64.msi
tagName      : A
href         : /vagrant/2.0.4/vagrant_2.0.4_x86_64.msi
data-arch    : x86_64
data-os      : windows
data-version : 2.0.4
data-product : vagrant
    #>

    Save-FileOnURL -URL "$ReleaseURL$($WinRelease.href)" -OutputPath $InstallrepoPath -Filename $WinRelease.outerText

    $InstallFilePath = Join-Path -Path $InstallrepoPath -ChildPath $WinRelease.outerText


    $package = Get-Package -ProviderName msi -Name "Vagrant" -ErrorAction Continue
    if(-not $package) {
        & msiexec /i $InstallFilePath INSTALLDIR="$privdir\tools\Vagrant" /norestart /passive /log $privdir\install_logs\vagrant.log
    }
    $VagrantPath = "$privdir\local_code\vagrant\.vagrant.d"
    New-DirectoryIfNotExists -dirname $VagrantPath
    $VagrantPath = $VagrantPath.Replace('\','/')
    [System.Environment]::SetEnvironmentVariable("VAGRANT_HOME",$VagrantPAth,"Machine")
    #[System.Environment]::SetEnvironmentVariable("VAGRANT_DEFAULT_PROVIDER","hyperv","Machine")
    [System.Environment]::SetEnvironmentVariable("VAGRANT_DEFAULT_PROVIDER","virtualbox","Machine")











    ##################################
    # Notepad++
    #
    # 64 bit. no plugin manager
    # https://notepad-plus-plus.org/repository/7.x/7.5.1/npp.7.5.1.bin.x64.zip
    # https://notepad-plus-plus.org/repository/7.x/7.5.1/npp.7.5.1.bin.zip

    try {

        [xml]$NPPVersionInfo = (Invoke-WebRequest -Uri "https://notepad-plus-plus.org/update/getDownloadUrl.php" -UseBasicParsing -ErrorAction stop).content


        $NppAppDir = Join-Path -Path $ToolsPath -ChildPath "Notepad++"
        $NppURL = $NPPVersionInfo.GUP.Location
        $DownloadPath = $InstallrepoPath

        $LOcalNPPFileName=($NppURL -split "/")[-1]
        #Save-FileOnURL -URL $NppURL -OutputPath $DownloadPath -Filename "notepad++.zip"
        $DownloadedFile = Save-FileOnURL -URL $NppURL -OutputPath $DownloadPath -Filename $LOcalNPPFileName

        $NppInstallDir = Join-Path -Path $ToolsPath -ChildPath "Notepad++"
        $NppPluginDir = Join-Path -Path $NppInstallDir -ChildPath "plugins"

        # http://nsis.sourceforge.net/Which_command_line_parameters_can_be_used_to_configure_installers
        Start-Process -FilePath $DownloadedFile -ArgumentList "/S /D=$NppInstallDir" -Wait -NoNewWindow

        # remove update dir to "disable" automatic updates
        rmdir -Path $(Join-Path -Path $NppInstallDir -ChildPath "updater") -Recurse -Verbose


        $NppAppBinPath = Join-Path -Path $NppAppDir -ChildPath "Notepad++.exe"
        if(-not $(Test-Path -Path $NppAppBinPath)) {
            Throw "Notepad++ was not found in the installation folder!"
        }


        $psdrive = Get-PSDrive -Name HKCR -ErrorAction SilentlyContinue
        if(-not $psdrive) {
            New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
        }


        # Associate files with notepad++
        $FileAssociations = @{
            "Microsoft.PowerShellData.1" = "edit";
            "Microsoft.PowerShellModule.1" = "edit";
            "Microsoft.PowerShellScript.1" = "edit";
            "inifile"="open";
            "inffile"="open";
            "txtfile"="open";
            "batfile"="edit";
            "cmdfile"="edit";
            "xmlfile"="edit";
            "Windows.XamlDocument"="edit";
        }

        $FileAssociations.Keys | ForEach-Object {

            $FType=$_
            $FTypeAction=$FileAssociations[$FType]
            Set-ItemProperty -Path HKCR:\$FType\shell\$FTypeAction\command -Name '(Default)' -Value "$NppAppBinPath `"%1`"" -verbose
        }

        # remove open for xml type
        Remove-Item -Path HKCR:\xmlfile\shell\Open -Recurse



        # start npp to initialize configs
        $NppProc = Start-Process -FilePath $(Join-Path -Path $NppInstallDir -ChildPath "Notepad++.exe") -PassThru -LoadUserProfile -WindowStyle Minimized
        Start-Sleep 5
        # Close Npp gracefully to make it write config files etc.
        $NppProc.CloseMainWindow()



        # Npp already have a solarized dark theme
        #Invoke-WebRequest -uri "https://raw.githubusercontent.com/walesmd/notepad-plus-plus-solarized/master/Solarized%20(Dark).xml" -OutFile "Solarized (Dark).xml"

        # copy settings
        Get-Content -Path  .\customizations\npp_config.xml.template -Raw | `
            _Expand-VariablesInString -VariableMappings @{
                APPDATA = $env:APPDATA;
            } | `
            Set-Content -Path $(join-path -Path $env:APPDATA -ChildPath "\Notepad++\config.xml")

        #Copy-Item -Path .\customizations\npp_config.xml.template -Destination $(join-path -Path $env:APPDATA -ChildPath "\Notepad++\config.xml") -Verbose

        # set font size in solarized theme
        $ThemePath = Join-Path -Path $env:APPDATA -ChildPath "Notepad++\themes\Solarized.xml"
        [xml]$Themedata = Get-Content -Path $ThemePath
        $WidgetStyles = @('Global override','Default style')
        $NppFontSize=14
        $Themedata.NotepadPlus.GlobalStyles.WidgetStyle | ForEach-Object {
            if($_.Name -in $WidgetStyles) {
                Write-Warning "Setting $($_.Name) fontSize=$NppFontSize"
                $_.fontSize = $NppFontSize.ToString()
            }
        }
        $Themedata.Save($ThemePath)


        # set tab configs
        # "132" seems to be 4 spaces and override default
        $NppLangFile =  $(Join-Path -Path $env:APPDATA -ChildPath "Notepad++\langs.xml")
        [xml]$NppLangData = get-content -Path $NppLangFile

        $NppTabSetting = "132"
        $NppLangs=@('python','bash','json','xml')
        $NppLangs | ForEach-Object {

            $LangNode = $NppLangData.NotepadPlus.Languages.SelectNodes("Language[@name=`"$_`"]")
            if($LangNode) {
                # use index 0 here because returned object is XPathNodeList
                if(-Not $Langnode[0].GetAttribute('tabSettings')) {
                    # https://stackoverflow.com/questions/30189997/how-to-add-attribute-if-it-doesnt-exist-using-powershell
                    Write-Warning "Adding tabSetting attribute to $_"
                    Add-XMLAttribute -Node $LangNode[0] -Name "tabSettings" -Value $NppTabSetting | Out-Null
                } else {
                    $LangNode[0].tabSettings = $NppTabSetting
                }
            }
        }
        $NppLangData.Save($NppLangFile)


        # Plugins for notepad++

        # first find the plugin list.

        $NppPluginListURL="https://nppxml.bruderste.in/pm/xml/plugins.zip"
        $NppPluginsUnzipDir = $(Join-Path -Path $env:TEMP -ChildPath "nppplugins")
        if( $(Test-Path -Path $NppPluginsUnzipDir) ) { rmdir $NppPluginsUnzipDir -Recurse -Verbose }
        $DownloadedFile = Save-FileOnURL -URL $NppPluginListURL -OutputPath $InstallRepoPath -Filename "nppplugins.zip"
        Expand-Archive -Path $DownloadedFile -DestinationPath $NppPluginsUnzipDir -Verbose
        [xml]$NppPluginList = Get-Content -Path $(Join-Path -Path $NppPluginsUnzipDir -ChildPath "PluginManagerPlugins.xml")


        # these must match name name in PlugManagerPlugins.xml
        $NppPluginsToInstall=@('XML Tools','Tidy2','HTML Tag','JSON Viewer')
        $NppPluginsToInstall | ForEach-Object {

            $InstallPLugin = $_
            $NppPlugin = $NppPluginList.SelectNodes("//plugin[@name=`"$InstallPLugin`"]")
            $PluginDownloadFileName = ("{0}.zip" -f [guid]::NewGuid())
            $PluginUnzipDir = $(Join-Path -Path $env:TEMP -ChildPath ([guid]::NewGuid()))

            Write-Debug ("NppPlugin={0} | DownloadPath={1} | Unzipdir={2}" -f $NppPlugin,$PluginDownloadFileName,$PluginUnzipDir) -Debug:$TRue

            throw "sdf"

            # the HEAD request might return forbidden, so wrap this in try/catch
            try {
                $RespHeaders = Invoke-WebRequest -Uri $NppPlugin[0].install.unicode.download -Method Head

                if($RespHeaders.Headers.'Content-Type' -like '*text/html*') {
                    Write-Warning "Download URL returned text/html. trying to find meta http-equiv=refresh"

                    $resp = Invoke-WebRequest -Uri $NppPlugin[0].install.unicode.download -UseBasicParsing
                    $resp.content -match "<meta http-equiv.*refresh.*" | Out-Null
                    $DownloadURL = ($Matches.Values -split '.*url=(.*)">')[1]
                    if($DownloadURL) {
                        #Invoke-WebRequest -Uri $NppPlugin[0].install.unicode.download -OutFile $PluginDownloadPath
                    }
                }
            } catch {
                Write-Warning ("Not able to HEAD {0}`r`n{1}" -f $NppPlugin[0].install.unicode.download, $_.Exception.Message)

                # if something went wrong with the HEAD request and download from meta refresh, then try and just get the URL
                $DownloadedFile = Save-FileOnURL -URL $NppPlugin[0].install.unicode.download -OutputPath $InstallRepoPath -Filename $PluginDownloadFileName
            }

            Expand-Archive -Path $DownloadedFile -DestinationPath  $PluginUnzipDir -Verbose
        }


        $NppLangs | ForEach-Object {

            $LangNode = $NppLangData.NotepadPlus.Languages.SelectNodes("Language[@name=`"$_`"]")
            if($LangNode) {
                # use index 0 here because returned object is XPathNodeList
                if(-Not $Langnode[0].GetAttribute('tabSettings')) {

                }
            }
        }



        <#

        $NppPlugins=@{
            XMLTOOLS=@{
                Name="XmlTools";
                DownloadURL="https://vorboss.dl.sourceforge.net/project/npp-plugins/XML%20Tools/Xml%20Tools%202.4.9%20Unicode/Xml%20Tools%202.4.9.2%20x86%20Unicode.zip"
                InstallCmds=@'
Copy-Item -Path $(Join-Path -Path $UnzipPath -ChildPath "dependencies\*.dll") -Destination $NppInstallDir  -Verbose;
Copy-Item -Path $(Join-Path -Path $UnzipPath -ChildPath "xmltools.dll") -Destination $NppPluginDir -Verbose;
'@
            };

        }

        $NppPlugins | ForEach-Object {
            $Plugin = $_.Values

            Write-Warning "Installing $($Plugin.Name)"

            $PluginDownloadPath = Join-Path -Path $InstallrepoPath -ChildPath "$($Plugin.Name).zip"
            $UnzipPath = $(Join-Path -Path $env:TEMP -ChildPath "npp_$($Plugin.Name)")


            Invoke-WebRequest -Uri $Plugin.DownloadURL -OutFile $PluginDownloadPath
            Expand-Archive -Path $PluginDownloadPath -DestinationPath $UnzipPath -Verbose

            Invoke-Expression -Command $Plugin.InstallCmds -Verbose

        }
        #>





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



    } catch {
        Write-Warning "Error: $($_.Exception.Message)"
    }



    ####################################################
    # OpenVPN
    #
    #Invoke-WebRequest -Uri 'https://swupdate.openvpn.org/community/releases/openvpn-install-2.3.17-I601-x86_64.exe' -UseBasicParsing -OutFile $privdir\_down\openvpn-install-2.3.17-I601-x86_64.exe
    #https://swupdate.openvpn.org/community/releases/openvpn-install-2.3.18-I602-x86_64.exe
    #https://swupdate.openvpn.org/community/releases/openvpn-install-2.4.6-I602.exe

    # Try and find the latest openvpn installer.
    <#
    href
    https://swupdate.openvpn.org/community/releases/openvpn-install-2.4.6-I602.exe
    https://swupdate.openvpn.org/community/releases/openvpn-install-2.3.18-I602-i686.exe
    https://swupdate.openvpn.org/community/releases/openvpn-install-2.3.18-I602-x86_64.exe
    #>
    $DownloadURL = Invoke-WebRequest -Uri "https://openvpn.net/index.php/open-source/downloads.html" -UseBasicParsing  | select -ExpandProperty Links | ? { $_.href -like 'https://*/releases/openvpn*.exe' } | Sort-Object href | select -first 1 href -ExpandProperty href

    $OutputFile = Save-FileOnURL -URL $DownloadURL -OutputPath $InstallRepoPath
    Import-Certificate -FilePath .\customizations\openssl_tap.pem -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher"

    #https://justcheckingonall.wordpress.com/2013/03/11/command-line-installation-of-openvpn/
    #https://b3it.blogspot.se/2014/06/openvpn-silent-intall-and-kaseya.html

    Start-Process -FilePath $OutputFile `
        -ArgumentList "/S /SELECT_SHORTCUTS=0 /SELECT_OPENVPN=1 /SELECT_SERVICE=1 /SELECT_TAP=1 /SELECT_OPENVPNGUI=1 /SELECT_ASSOCIATIONS=0 /SELECT_OPENSSL_UTILITIES=0 /SELECT_EASYRSA=0 /SELECT_PATH=1 /SELECT_OPENSSLDLLS=1 /SELECT_LZODLLS=1 /SELECT_PKCS11DLLS=1" `
        -NoNewWindow -Wait

    get-service | ? { $_.Name -like 'OpenVPN*'} | stop-service -PassThru | Set-Service -StartupType Manual



    ######################################################
    # MoveToDesktop
    # https://github.com/Eun/MoveToDesktop/releases
    #
    $proj = Get-GitHubProjectLatestRelease -Project "Eun/MoveToDesktop" -FileNameMatch "MoveToDesktop*.zip"
    Save-FileOnURL -URL $proj.browser_download_url -OutputPath $InstallrepoPath -Filename "MoveToDesktop-latest.zip"
    $DEstinationPath = $(Join-Path -Path $ToolsPath -ChildPath "MoveToDesktop")
    mkdir -Path $DEstinationPath
    Expand-Archive -Path $(Join-Path -Path $InstallrepoPath -ChildPath "MoveToDesktop-latest.zip") -DestinationPath $DestinationPath

    Add-ProgramToRegistryAutorun -ProgramName "MoveToDeskTop" -exepath $(Join-Path -Path $DestinationPath -ChildPath "MoveToDesktop.exe")



    ######################################################
    # Path Copy Copy
    # https://github.com/clechasseur/pathcopycopy/releases/download/14.0/PathCopyCopy14.0.exe
    #
    # PathCopyCopy.exe /?

    $Package = get-package | ? { $_.Name -like '*path copy copy*' }
    if(-Not $package) {

        $proj = Get-GitHubProjectLatestRelease -Project "clechasseur/pathcopycopy" -FileNameMatch "PathCopyCopy*.exe"
        #$DownloadURL = "https://github.com/clechasseur/pathcopycopy/releases/download/14.0/PathCopyCopy14.0.exe"
        Save-FileOnURL -URL $proj.browser_download_url -OutputPath $InstallrepoPath -Filename "PathCopyCopy.exe"

        $InstallFile = join-path -Path $InstallrepoPath -ChildPath "PathCopyCopy.exe"
        $InstallLogPath = join-path -Path $privdir -ChildPath "install_logs\pathcopycopy.log"
        Start-Process -FilePath $InstallFile -ArgumentList "/SILENT /LOG=`"$InstallLogPath`"" -Wait -NoNewWindow
    }



    ###########################################################
    #
    # Greenshot
    #
    # https://github.com/greenshot/greenshot/

    $GreenshotConfigDir = $(Join-Path -Path $env:APPDATA -ChildPath "Greenshot")
    if(-not $(Test-Path -Path $GreenshotConfigDir)) { mkdir $GreenshotConfigDir }
    copy -Path .\customizations\Greenshot.ini -Destination $GreenshotConfigDir

    $Package = $(Get-Package | ? { $_.Name -like 'Greenshot*'} )
    if(-not $package) {

        $proj = Get-GitHubProjectLatestRelease -Project "greenshot/greenshot" -FileNameMatch "Greenshot-INSTALLER*-RELEASE.exe"
        Save-FileOnURL -URL $proj.browser_download_url -OutputPath $InstallrepoPath -Filename "Greenshot.exe"

        $InstallFile = Join-Path -Path $InstallrepoPath -ChildPath "Greenshot.exe"
        $InstallLogPath = join-path -Path $privdir -ChildPath "install_logs\greenshot.log"

        Start-Process -FilePath $InstallFile -ArgumentList "/SILENT /LOG=`"$InstallLogPath`"" -Wait -NoNewWindow

        #Invoke-WebRequest -Uri 'https://github.com/greenshot/greenshot/releases/download/Greenshot-RELEASE-1.2.10.6/Greenshot-INSTALLER-1.2.10.6-RELEASE.exe' -UseBasicParsing -OutFile $privdir\_down\Greenshot-INSTALLER-1.2.10.6-RELEASE.exe
        #Unblock-File -Path "$privdir\_down\Greenshot-INSTALLER-1.2.10.6-RELEASE.exe"
    }






    ############################################################
    # Wireshark
    # https://1.eu.dl.wireshark.org/win64/Wireshark-win64-2.4.1.exe
    #
    # TODO: silen install
    #
    $Package = $(Get-Package | ? { $_.Name -like 'Wireshark*'} )
    if(-not $Package) {
        <#
        g_string_printf(update_url_str, "https://www.wireshark.org/%s/%u/%s/%s/%s/%s/en-US/%s.xml",
                         SU_SCHEMA_PREFIX,
                         SU_SCHEMA_VERSION,
                         SU_APPLICATION,
                         VERSION,
                         SU_OSNAME,
                         arch,
                         chan_name);

     https://www.wireshark.org/update/0/Wireshark/2.4.3/Windows/x86-64/en-US/stable.xml
        #>
        $SimulateWiresharkVersion="2.4.3"
        $WiresharkVersionURL="https://www.wireshark.org/update/0/Wireshark/{0}/Windows/x86-64/en-US/stable.xml" -f $SimulateWiresharkVersion
        [xml]$WiresharkVersionInfo = invoke-webrequest -Uri $WiresharkVersionURL -UseBasicParsing -DisableKeepAlive | select -ExpandProperty Content

        $OutputFile = Save-FileOnURL -URL $WiresharkVersionInfo.rss.channel.item.enclosure.url -OutputPath $InstallRepoPath

        # WinPcap does not install when running silently, so skip exploring that option for now
        & $OutputFile
    }


    #############################################################
    #
    # SoapUI
    #
    # http://smartbearsoftware.com/distrib/soapui/5.2.1/SoapUI-x64-5.2.1.exe
    $OutputFile = Save-FileOnURL -URL "http://smartbearsoftware.com/distrib/soapui/5.2.1/SoapUI-x64-5.2.1.exe" -OutputPath $InstallRepoPath

    # https://community.smartbear.com/t5/SoapUI-Open-Source/Silent-Install-Option/td-p/10921
    Start-Process -FilePath $OutputFile -ArgumentList "-q" -NoNewWindow -Wait

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

    @'
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
'@ | Set-Content -Path $ManifestFile -Encoding UTF8 -Force






    #######################################################
    #
    # MS SQL Management Studio 2016
    #
    $DownloadedFile = Save-FileOnURL -URL "https://download.microsoft.com/download/0/D/2/0D26856F-E602-4FB6-8F12-43D2559BDFE4/SSMS-Setup-ENU.exe" -OutputPath $InstallRepoPath -Filename "SSMS-Setup-ENU.EXE"
    Start-Process -FilePath $DownloadedFile -ArgumentList "/install /quiet /norestart"

    <#
    # $CorpRepo\Program_Licens\Microsoft en\SQL Server\SQL Server 2016 Enterprise Core 64 bit\Management Studio MS SQL 2016\SSMS-Setup-ENU.exe /?
    $Package = $(get-package -name "SQL Server 2016 Management Studio" -providername msi)
    if(-not $package) {
        Start-Process -FilePath "$CorpRepo\Program_Licens\Microsoft en\SQL Server\SQL Server 2016 Enterprise Core 64 bit\Management Studio MS SQL 2016\SSMS-Setup-ENU.exe" `
            -ArgumentList "/Instal /Quiet /NoRestart" -Wait -NoNewWindow
    } else {
        Write-Warning "Not installing SQL management studio, it appears installed already."
    }
    #>



    #########################################################
    # ConEmu
    # https://conemu.github.io/en/AutoInstall.html
    # powershell -NoProfile -ExecutionPolicy Unrestricted -Command "iex ((new-object net.webclient).DownloadString('https://conemu.github.io/install.ps1'))"

    $ConEmuInstallPath = Join-Path -Path "$privdir\tools" -ChildPath "ConEmu"

    if(-not $(Test-Path -Path $ConEmuInstallPath) ) {

        $reldata = Get-GitHubProjectLatestRelease -Project "Maximus5/ConEmu"  -FileNameMatch 'ConEmuSetup*.exe'
        if($reldata.browser_download_url) {
            $OutputFile = Save-FileOnURL -URL $reldata.browser_download_url -OutputPath $InstallRepoPath

            # Install
            & $OutputFile

        } else {
            Write-Warning "Could not get URL for ConEmu"
        }



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

        # TODO: Download fails because of invalid cert. Need to get code for accepting cert into start-process command string.
        Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Unrestricted -Command `"$ConEmuInstallCmd; iex ((new-object net.webclient).DownloadString('https://conemu.github.io/install2.ps1'))`"" -NoNewWindow -Wait
        New-ProgramShortcut -TargetPath $(Join-Path -Path $ConEmuInstallPath -ChildPath "ConEmu64.exe") -IconFileName "ConEmu" -WorkingDirectory $ConEmuInstallPath
        Copy-Item -Path .\customizations\ConEmu.xml -Destination $ConEmuInstallPath -Force -Verbose
    }


    ###################################################
    #
    # java
    #
    Start-Process -FilePath "$crepo\Program\java\Windows\jre-8u144-windows-x64.exe" -ArgumentList "AUTO_UPDATE=Disable INSTALL_SILENT=Enable" -NoNewWindow -Wait

    #
    # Corretto 8
    #
    $Corretto8URL = "https://corretto.aws/downloads/latest/amazon-corretto-8-x64-windows-jdk.zip"
    $Corretto8URL = "https://corretto.aws/downloads/resources/8.282.08.1/amazon-corretto-8.282.08.1-windows-x64-jdk.zip"
    $CorrettoSavePath = Save-FileOnURL -URL $Corretto8URL -OutputPath $InstallrepoPath

    $CorrettoTempPath = Join-Path -Path $env:TEMP -ChildPath ([guid]::NewGuid())
    mkdir -Path $CorrettoTempPath -ErrorAction Continue

    Expand-Archive -Path $CorrettoSavePath -DestinationPath $CorrettoTempPath 
    $CorrettoVersionDir = dir $CorrettoTempPath -Filter 'jdk*'

    $JDKDir = Split-Path -Path $CorrettoVersionDir -Leaf
    $JDKInstallPath = "$ToolsPath\Corretto8"

    if(-not $(Test-Path $JDKInstallPath)) {
        mkdir $JDKInstallPath -ErrorAction SilentlyContinue
        move-item -Path ($CorrettoVersionDir.FullName) -Destination $JDKInstallPath  # moves the whole dir

        # Fix ACLs on extracted files/dirs. They are not inheriting permissions from parent dir.

        New-Item -Path c:\JDK8 -ItemType Junction -Value "$JDKInstallPath\$JDKDir" -Force

        $MachinePathEnv = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine)
        [Environment]::SetEnvironmentVariable("Path", "$JDKInstallPath\$JDKDir" + ";" + $MachinePathEnv,
            [EnvironmentVariableTarget]::Machine)

        [Environment]::SetEnvironmentVariable("JAVA_HOME", "$JDKInstallPath\$JDKDir",
            [EnvironmentVariableTarget]::Machine)
    } else {
        Write-Warning "$JDKInstallPath already exists!"
    }


    #
    # Corretto 11
    #
    $Corretto11URL = "https://corretto.aws/downloads/latest/amazon-corretto-11-x64-windows-jdk.zip"
    $CorrettoSavePath = Save-FileOnURL -URL $Corretto11URL -OutputPath $InstallrepoPath

    $CorrettoTempPath = Join-Path -Path $env:TEMP -ChildPath ([guid]::NewGuid())
    mkdir -Path $CorrettoTempPath -ErrorAction Continue

    Expand-Archive -Path $CorrettoSavePath -DestinationPath $CorrettoTempPath 
    $CorrettoVersionDir = dir $CorrettoTempPath -Filter 'jdk*'

    $JDKDir = Split-Path -Path $CorrettoVersionDir -Leaf
    $JDKInstallPath = "$ToolsPath\Corretto11"
    if(-not $(Test-Path $JDKInstallPath)) {
        mkdir $JDKInstallPath -ErrorAction SilentlyContinue
        move-item -Path ($CorrettoVersionDir.FullName) -Destination $JDKInstallPath  # moves the whole dir
        New-Item -Path c:\JDK11 -ItemType Junction -Value "$JDKInstallPath\$JDKDir" -Force


    } else {
        Write-Warning "$JDKInstallPath already exists!"
    }


    ###################################################
    #
    # Maven
    #
    $MavenURL = "https://ftp.acc.umu.se/mirror/apache.org/maven/maven-3/3.8.1/binaries/apache-maven-3.8.1-bin.zip"
    $OutputFile = Save-FileOnURL -URL $MavenURL -OutputPath $ToolsPath 
    $TargetPath = "$ToolsPath\Maven"

    mkdir $TargetPath -ErrorAction SilentlyContinue
    Expand-Archive -Path $Outputfile -DestinationPath $TargetPath

    $InstalledMavenPath = dir $TargetPath | Sort-Object -Property CreationTime -Descending | select -first 1

    $MachinePathEnv = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine)
    $NewPath = ("{0};{1}\bin" -f $MachinePathEnv, $($InstalledMavenPath.FullName))
    [Environment]::SetEnvironmentVariable("Path", $NewPath, [EnvironmentVariableTarget]::Machine)


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
    $OutputPath = $InstallRepoPath
    $DownloadedFile = Save-FileOnURL -URL "https://go.microsoft.com/fwlink/?Linkid=850641"  -OutputPath $OutputPath -Filename "vSCode_latest.zip"

    $TargetPath = $(Join-Path -Path $ToolsPath -ChildPath "VSCode")
    if($(Test-Path -Path $TargetPath)) {
        Write-Warning ('"{0}" already exist' -f $TargetPath)
        $TS = get-date -UFormat "%Y%M%d%H%M%S"
        $BackupPath = $(Join-Path -Path $ToolsPath -ChildPath ("VSCode_old_{0}" -f $TS))
        if($(Test-path -Path $BackupPath)) { Remove-Item -Path $BackupPath -Recurse }
        Move-Item -Path $TargetPath -Destination $BackupPath
        Write-Warning ('"{0}" Moved to {1}' -f $TargetPath, $BackupPath)
    }
    Expand-Archive -Path $DownloadedFile -DestinationPath $TargetPath -Force

    New-ProgramShortcut -TargetPath $(Join-Path -Path $ToolsPath -ChildPath "VSCode\code.exe") -IconFileName "Visual Studio Code"

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
    # Visual studio community ed
    #
    #https://download.visualstudio.microsoft.com/download/pr/d125163a-cf26-489a-b62e-94995a66d7c5/1ff3b2c80236499af4ef5bd802277f64/vs_community.exe
    #https://download.visualstudio.microsoft.com/download/pr/067fd8d0-753e-4161-8780-dfa3e577839e/771a4c18e31ccc341097af13302792331817ae81fce20f8c99799163d87733d4/vs_Community.exe




    ################################################
    #
    # Atom editor
    #
    # https://github.com/atom/atom/releases/download/v1.21.0/atom-x64-windows.zip
    $OutputPath = $InstallRepoPath

    $AtomDownloadURL = Get-GitHubProjectLatestRelease -Project "atom/atom" -FileNameMatch "atom-x64-windows.zip" -ReturnProperty "browser_download_url"

    if(-not $AtomDownloadURL) {
        Throw "Could not find atom download URL"
    }

    #Save-FileOnURL -URL "https://github.com/atom/atom/releases/download/v1.25.1/atom-x64-windows.zip"  -OutputPath $OutputPath -Filename "atom-x64-windows.zip"
    $DownloadedFile = Save-FileOnURL -URL $AtomDownloadURL  -OutputPath $OutputPath -Filename "atom-x64-windows.zip"


    $DestinationPath = $(Join-Path -Path $privdir -ChildPath "tools\Atom")
    Expand-Archive -Path $DownloadedFile -DestinationPath $DestinationPath -Force
    if( $(Test-Path -Path $(Join-Path -Path $DestinationPath -ChildPath "Atom x64") ) ) {
        Move-Item -Path $(Join-Path -Path $DestinationPath -ChildPath "Atom x64\*") -Destination $DestinationPath
    }

    $SettingsDir = Join-Path -Path $DestinationPath -ChildPath "settings"
    mkdir $SettingsDir

    # set config dir
    [environment]::SetEnvironmentVariable("ATOM_HOME",$SettingsDir,[System.EnvironmentVariableTarget]::User)

    # Add icon to start menu
    New-ProgramShortcut -TargetPath $(join-path -Path $DestinationPath -ChildPath "atom.exe") `
                        -WorkingDirectory $privdir `
                        -IconPath "$($env:APPDATA)\Microsoft\Windows\Start Menu\Programs\" -IconFileName Atom


     # shell integration
    # https://github.com/notepad-plus-plus/notepad-plus-plus/issues/92
    #https://blogs.msdn.microsoft.com/lior/2009/06/18/what-no-hkcr-in-powershell/
    $psdrive = Get-PSDrive -Name HKCR -ErrorAction SilentlyContinue
    if(-not $psdrive) {
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
    }
    New-Item -Path HKCR:\*\Shell\Atom -Value "Edit with Atom"
    New-Item -Path HKCR:\*\Shell\Atom\command -Value "`"$(Join-Path -Path $DestinationPath -ChildPath "atom.exe")`" `"%1`""

    New-Item -Path HKCR:\*\Shell\AtomNewWindow -Value "Edit with Atom in new window"
    New-Item -Path HKCR:\*\Shell\AtomNewWindow\command -Value "`"$(Join-Path -Path $DestinationPath -ChildPath "atom.exe")`" --new-window `"%1`""

    # new-ItemProperty seems to have trouble with "*"
    # https://powershell.org/forums/topic/cant-set-new-itemproperty-to-registry-path-containing-astrix/
    #New-ItemProperty -Path HKCR:\*\Shell\VSCode -Name Icon -Value "`"$(Join-Path -Path $privdir -ChildPath "tools\VSCode\code.exe")`""
    $hive = [Microsoft.Win32.RegistryKey]::OpenBaseKey('ClassesRoot', 'Default')
    $subkey = $hive.OpenSubKey('*\shell\Atom', $true)
    $subkey.SetValue('Icon', "$(Join-Path -Path $DestinationPath -ChildPath "atom.exe")", 'String')

    # $privdir\tools\atom\resources\app\apm\bin\apm.cmd install <package>
    $APMPath = Join-Path -Path $DestinationPath -ChildPath "resources\app\apm\bin\apm.cmd"
    if( $(Test-Path -Path $APMPath) ) {


        $AtomPackages = @('split-diff'
                        ,'minimap-split-diff'
                        ,'language-powershell'
                        ,'pretty-json'
                        ,'highlight-selected'
                        ,'editorconfig'
                        ,'file-icons'
                        ,'git-plus'
                        ,'block-cursor'
                        ,'file-types'
                        ,'language-batchfile'
                        ,'minimap'
                        ,'minimap-highlight-selected'
                    )
        $AtomPackages | Foreach-Object {
            & $APMPath install $_
        }



    } else {
        Write-Warning "apm.cmd was not found!"
    }



    ###############################################
    # Choclatery
    $ChocoCmd = @'
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
'@

    $ChocoCmdBytes = [System.Text.Encoding]::Unicode.GetBytes($ChocoCmd)
    $ChocoCmdEnc = [Convert]::ToBase64String($ChocoCmdBytes)

    Start-Process -FilePath $([System.Environment]::ExpandEnvironmentVariables("%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe")) `
        -ArgumentList "-ExecutionPolicy Bypass -EncodedCommand $ChocoCmdEnc" -Wait -NoNewWindow






    ################################################
    #
    # WiLMA Windows Layout Manager
    #
    # Needs to be started elevated to be able to enumerate windows
    #
    $DownloadURL = "http://www.stefandidak.com/wilma/winlayoutmanager.zip"
    $OutputPath = $(Join-Path -Path $privdir -ChildPath "installrepo")
    Save-FileOnURL -URL $DownloadPath  -OutputPath $OutputPath -Filename "winlayoutmanager.zip"

    $DestinationPath = $(Join-Path -Path $privdir -ChildPath "tools\WiLMA")
    Expand-Archive -Path $(Join-Path -Path $OutputPath -ChildPath "winlayoutmanager.zip") -DestinationPath $DestinationPath -Force

    $ExePath = join-path -Path $DestinationPath -ChildPath "wilma.exe"

    # Add icon to start menu
    New-ProgramShortcut -TargetPath $ExePath `
                        -WorkingDirectory $privdir `
                        -IconPath "$($env:APPDATA)\Microsoft\Windows\Start Menu\Programs\" -IconFileName Wilma

    # exe needs to run as admin
    Add-CompatibilitySettings -ProgramPath $ExePath -CompatModes "RUNASADMIN"



    ########################################################
    #
    # Terminals remote connection manager
    #
    #$OutputPath = $(Join-Path -Path $privdir -ChildPath "installrepo")
    #Save-FileOnURL -URL "https://github.com/Terminals-Origin/Terminals/releases/download/4.0.1/TerminalsSetup_4.0.1.msi"  -OutputPath $OutputPath -Filename "TerminalsSetup_4.0.1.msi"

    #& msiexec /i $(join-path -Path $OutputPath -ChildPath "TerminalsSetup_4.0.1.msi") /norestart /passive /log $(join-path -Path $privdir -ChildPath "install_logs\terminals_setup.log")





    ########################################################
    #
    # Remote desktop connection manager
    #
    $DownloadURL = "https://download.microsoft.com/download/A/F/0/AF0071F3-B198-4A35-AA90-C68D103BDCCF/rdcman.msi"
    $DownloadPath = $InstallRepoPath

    $DownloadedFile = Save-FileOnURL -URL $DownloadURL -OutputPath $DownloadPath -Filename "rdcman.msi"

    & msiexec /i $DownloadedFile /norestart /passive /log $(join-path -Path $privdir -ChildPath "install_logs\rdcman.log")


    ###############################################
    # MIsc stuff

    # update powershell help
    update-help

    # create .aws directory
    New-DirectoryIfNotExists -dirname  $(Join-Path -Path $HomePath -ChildPath ".aws")



    #############################################
    #
    # Cygwin
    #
    #http://www.cygwin.com/faq/faq.html#faq.setup.cli
    #https://stackoverflow.com/questions/745275/can-i-script-a-cygwin-install-to-include-certain-packages#

    #TODO: automate cygwin install from a list of packages

    $DownloadURL = "http://www.cygwin.com/setup-x86_64.exe"
    $DownloadedFile = Save-FileOnURL -URL $DownloadURL -OutputPath $InstallrepoPath -Filename "setup-x86_64.exe"

    mkdir $(Join-Path -Path $privdir -ChildPath "tools\cygwin\pkg")
    mkdir $(Join-Path -Path $privdir -ChildPath "tools\cygwin\current")

    $InstallPath = Join-Path -Path $ToolsPath -ChildPath "cygwin\current"
    $PkgPath = Join-Path -Path $ToolsPath -ChildPath "cygwin\pkg"

    $CygwinPackages=@(
        "rxvt","wget","openssl","mc","nc","ncftp","vim",
        "curl","links","lynx","arj","unzip","ascii","attr",
        "corkscrew","fdupes","hexedit","lftp","lv","mintty",
        "openldap","bind-utils","ca-certificates","rpm",
        "mysql-client","joe","cpio","ddrescue","mkisofs",
        "screen","wodim","md5deep","openssh","ping","inetutils",
        "whois","binutils","util-linux","rsync","httping",
        "dos2unix","sharutils","xxd","git","bash-completion",
        "python","python-setuptools","tmux","pv","gnupg","zip",
        "procps-ng","xmlsec1","jq","python3","python2-ipython",
        "python-ipython","python3-ipython"
    )
    & $DownloadedFile --quiet-mode --download --site http://cygwin.uib.no --local-package-dir $PkgPath --packages $($CygwinPackages -join ",")
    & $DownloadedFile --quiet-mode --local-install --local-package-dir $PkgPath --root  $InstallPath --packages  $($CygwinPackages -join ",")

    $InitScript=@'
cd ~
ln -s %CYGPRIVDIR% local
git clone https://github.com/Winterlabs/shellsettings

# git aliases
git config --global alias.lg "log --pretty='%Cred%h%Creset |%C(yellow)%d%Creset %s %Cgreen(%cr)%Creset %C(cyan)[%an]%Creset'"

# bash-git-prompt
#git clone https://github.com/magicmonty/bash-git-prompt.git .bash-git-prompt --depth=1

#cat << 'EOF' >> ~/.bashrc
#GIT_PROMPT_ONLY_IN_REPO=1
#source ~/.bash-git-prompt/gitprompt.sh
#EOF

cat << 'EOF' >> ~/.bash_profile
PS1="\[\e]0;\w\a\]\n\[\e[32m\]\u@\h \[\e[33m\]\w\[\e[0m\]\n\[\033[0;37m\]\t \[\033[0;0m\]\$ "
export PS1
EOF

cat << 'EOF' >> ~/.bashrc
PS1="\[\e]0;\w\a\]\n\[\e[32m\]\u@\h \[\e[33m\]\w\[\e[0m\]\n\[\033[0;37m\]\t \[\033[0;0m\]\$ "
export PS1
EOF



# APT-cyg
mkdir ~/prog
cd ~/prog
curl -k https://raw.githubusercontent.com/transcode-open/apt-cyg/master/apt-cyg > apt-cyg
install apt-cyg /bin


# PIP
wget https://bootstrap.pypa.io/get-pip.py
python get-pip.py

# AWS cli
pip install awscli
ln -s %WINHOMEAWSDIR% ~/.aws

# pyserve
pip install pyserve

#boto3
pip install boto3

# Solarized color theme
# https://github.com/mavnn/mintty-colors-solarized
curl -s https://raw.githubusercontent.com/mavnn/mintty-colors-solarized/master/.minttyrc.dark >> ~/.minttyrc

# block cursor for mintty
echo "CursorType=block" >> ~/.minttyrc


# python virtual env
# http://atbrox.com/2009/09/21/how-to-get-pipvirtualenvfabric-working-on-cygwin/
easy_install-2.7 virtualenv
easy_install-2.7 virtualenvwrapper
mkdir ~/.virtualenvs


cat <<'EOF' >>~/.bash_aliases
#alias gitbranch='git branch -vv -a'
alias gits='git status'
EOF


cat <<'EOF' >>~/.bashrc
settitle() {
    title=$1
    [ -z "$title" ] && title="bash"
    printf "\033k$title\033\\"
}

gitbranch() {
    [ -z $1 ] && git branch -vv -a || git branch -vv -a | grep -i $1
}
settitle () {
    title=$1;
    [ -z "$title" ] && title="bash";
    printf "\033k$title\033\\"
}


if [ -f "${HOME}/.bash_aliases" ]; then
  source "${HOME}/.bash_aliases"
fi

# handle ssh-agent
if [ ! -e ~/.ssh_agent_env ]; then
  echo ".ssh_agent_env not found. executing ssh-agent..."
  ssh-agent 1>~/.ssh_agent_env
  eval `cat ~/.ssh_agent_env`
  ssh-add
else
  echo ".ssh_agent_env found. reading env file..."
  eval `cat ~/.ssh_agent_env`
  ps -p $SSH_AGENT_PID | grep -q "ssh-agent"
  status=$?
  if [ $status -gt 0 ]; then
    echo "ssh-agent pid in .ssh_agent_env looks stale. re-executing..."
    ssh-agent 1>~/.ssh_agent_env
    eval `cat ~/.ssh_agent_env`
    ssh-add
  else
    echo "found an ssh-agent with pid $SSH_AGENT_PID"
  fi
fi

for service in rsyslog cron; do
    pgrep $service 1>/dev/null 2>&1 || service $service start
done

# run stuff when executed from TMUX
if [[ $TMUX ]]; then
    cd ~/local/
fi

export WORKON_HOME=$HOME/.virtualenvs
export PIP_VIRTUALENV_BASE=$WORKON_HOME
source /usr/bin/virtualenvwrapper.sh
EOF


export WORKON_HOME=$HOME/.virtualenvs
export PIP_VIRTUALENV_BASE=$WORKON_HOME
source /usr/bin/virtualenvwrapper.sh
'@


    ($InitScript | _Expand-VariablesInString -VariableMappings @{
        WINHOMEAWSDIR = ConvertTo-CygwinPath -Path  $(Join-Path -Path $(join-path -path $env:HOMEDRIVE -childpath $env:HOMEPATH) -childpath ".aws")
        CYGPRIVDIR = ConvertTo-CygwinPath -Path $privdir

    }).replace("`r`n","`n") | Set-Content -Path $(Join-Path -Path $InstallPath -ChildPath "home\init.sh") -Encoding UTF8 -NoNewline


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


    #############################################
    #
    # Misc stuff
    #

    # Certificate msc
    $CustomizationPath = $PSScriptRoot
    if(-not $CustomizationPath) {
        $CustomizationPath = (get-location).path
    }

    $CustomizationPath = Join-Path -Path $CustomizationPath -ChildPath "customizations"

    $DesktopLocation = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Desktop"
    Copy -Path $(Join-Path -Path $CustomizationPath -ChildPath "Certificates.msc") -Destination $DesktopLocation -Verbose

    $StartMenuLocation = Get-ItemPropertyValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Start Menu"
    Copy -Path $(Join-Path -Path $CustomizationPath -ChildPath "Certificates.msc") -Destination $StartMenuLocation -Verbose



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



    #############################################
    #
    # KeepassXC
    #
    $DownloadURL = Get-GitHubProjectLatestRelease -Project "keepassxreboot/keepassxc" -FileNameMatch "KeePassXC*Win64-Portable.zip" -ReturnProperty "browser_download_url"
    $DownloadedFile = Save-FileOnURL -URL $DownloadURL -OutputPath $InstallrepoPath -Filename "KeepassXC_latest.zip"

    $DestinationPath = $(Join-Path -Path $ToolsPath -ChildPath "KeePassXC")
    Expand-Archive -Path $DownloadedFile -DestinationPath $DestinationPath -Force

    # TODO: Fix that keepass unzips into a subfolder

    copy .\customizations\keepassxc.ini $DestinationPath -Verbose



    $ExePath = Join-Path -Path $DestinationPath -ChildPath "KeePassXC.exe"

    # Add icon to start menu
    New-ProgramShortcut -TargetPath $ExePath `
                        -WorkingDirectory $DestinationPath `
                        -IconPath "$($env:APPDATA)\Microsoft\Windows\Start Menu\Programs\" -IconFileName KeePassXC


    #############################################
    #
    # VirtualBox
    #
    #$LatestVersionURL = "https://download.virtualbox.org/virtualbox/LATEST-STABLE.TXT"
    $LatestVersionURL = "https://download.virtualbox.org/virtualbox/LATEST.TXT"
    $data = Invoke-WebRequest -Uri $LatestVersionURL -UseBasicParsing -DisableKeepAlive
    $Version = $data.Content.Replace("`n","")
    $VersionURL = "https://download.virtualbox.org/virtualbox/$Version/"

    # try and find latest version
    <#
outerHTML                                                                       tagName href
---------                                                                       ------- ----
<a href="VirtualBox-5.2.10-122088-Win.exe">VirtualBox-5.2.10-122088-Win.exe</a> A       VirtualBox-5.2.10-122088-Win.exe
<a href="VirtualBox-5.2.10-122406-Win.exe">VirtualBox-5.2.10-122406-Win.exe</a> A       VirtualBox-5.2.10-122406-Win.exe
    #>
    $data = Invoke-WebRequest -Uri $VersionURL -UseBasicParsing -DisableKeepAlive
    $link = $data.Links | ? { $_.href -like '*win*.exe' } | Sort-Object -Property href -Descending | select -first 1

    $DownloadedFile = Save-FileOnURL -URL "${VersionURL}$($link.href)" -OutputPath $InstallrepoPath -Filename $link.href

    & $DownloadedFile


    & "c:\ao\tools\VirtualBox\VBoxManage.exe" setproperty machinefolder $(Join-Path -Path $privdir -ChildPath "VMs\machines")
    & "c:\ao\tools\VirtualBox\VBoxManage.exe" setextradata global GUI/UpdateDate never


    #############################################
    #
    # BrowserSelect
    #
    # https://github.com/zumoshi/BrowserSelect




    #############################################
    #
    # Postman
    #
    # https://dl.pstmn.io/download/latest/win64



    #############################################
    #
    # Python 3 for windows
    #
    # https://docs.python.org/3/using/windows.html
    #
    $DownloadURL="https://www.python.org/ftp/python/3.7.3/python-3.7.3-amd64.exe"
    $LocalFileName=Save-FileOnURL -URL $DownloadURL -OutputPath $InstallRepoPath
    $InstallDir=$(Join-Path -Path $ToolsPath -ChildPath "Python3")

    Start-Process -FilePath $LocalFileName  -Wait -NoNewWindow `
        -ArgumentList @("TargetDir=`"$InstallDir`""
                       ,"AssociateFiles=0"
                       ,"InstallLauncherAllUsers=0"
                       ,"/passive"
                       )

    <#
    pip install boto3 requests pylint
    #>


    #############################################
    #
    # Windows 10 1909 things. Terminal, winget
    #

    # requires c++ redist 14
    # https://www.microsoft.com/en-us/download/confirmation.aspx?id=53175
    $DownloadURL = "https://download.microsoft.com/download/B/E/1/BE1F235A-836D-42AC-9BC1-8F04C9DA7E9D/vc_uwpdesktop.140.exe"
    $OutputFile = Save-FileOnURL -URL $DownloadURL -OutputPath $InstallrepoPath
    Start-Process -FilePath $OutputFile `
        -ArgumentList "/install /log $(Join-Path -Path $privdir -ChildPath "install_logs\vc_uwpdesktop.140.log")`""  `
         -NoNewWindow -Wait


    # winget
    $reldata = Get-GitHubProjectLatestRelease -Project "microsoft/winget-cli"  -FileNameMatch 'Microsoft.DesktopAppInstaller*.appxbundle'
    if($reldata.browser_download_url) {
        $OutputFile = Save-FileOnURL -URL $reldata.browser_download_url -OutputPath $InstallRepoPath

        # Install
        & $OutputFile
    }



    # microsoft terminal
    & winget install --id=Microsoft.WindowsTerminal -e


    # powershell prompt & Themes
    # https://docs.microsoft.com/en-us/windows/terminal/tutorials/powerline-setup

    # cascadia code font
    $reldata = Get-GitHubProjectLatestRelease -Project "microsoft/cascadia-code"  -FileNameMatch 'CascadiaCode_*.zip'
    if($reldata.browser_download_url) {
        $OutputFile = Save-FileOnURL -URL $reldata.browser_download_url -OutputPath $InstallRepoPath
        $UnzipPath = Join-Path -Path $env:TEMP -ChildPath $([GUID]::NewGuid())
        mkdir $UnzipPath -ErrorAction Continue
        Expand-Archive -Path $OutputFile -DestinationPath $UnzipPath

        ii $(Join-Path -Path $UnzipPath -ChildPath "ttf\CascadiaCodePL.ttf")
    }


    # Oh My PoSH - Themes
    Install-Module oh-my-posh -Scope CurrentUser


    # "fontFace": "Cascadia Code PL"
    # mkdir $ThemeSettings.MyThemesLocation
    # copy C:\Users\aostlund\OneDrive - Infor\Documents\WindowsPowerShell\Modules\oh-my-posh\2.0.440\Themes\Paradox.psm1  $ThemeSettings.MyThemesLocation\aostlund.psm1


    #############################################
    #
    # WinSCP
    #
    $DownloadURL="https://winscp.net/download/files/201806121356a4c9098191dd126bc346956e8718b798/WinSCP-5.13.2-Portable.zip"
    Save-FileOnURL -URL $DownloadURL -OutputPath $InstallrepoPath -Filename "WinSCP-5.13.2-Portable.zip"
    $InstallPath = Join-Path -Path $ToolsPath -ChildPath "WinSCP"
    Expand-Archive -Path $(Join-Path -Path $InstallrepoPath -ChildPath "WinSCP-5.13.2-Portable.zip") -DestinationPath $InstallPath -Force

    ii $ToolsPath

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


Function _Install-GitForWindows {
    [cmdletBinding()]
    Param(

    )

    # If -debug is set, change $DebugPreference so that output is a little less annoying.
    #    http://learn-powershell.net/2014/06/01/prevent-write-debug-from-bugging-you/
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }

    ###################################
    #
    # git for windows
    #
    $reldata = Get-GitHubProjectLatestRelease -Project "git-for-windows/git"  -FileNameMatch 'Git*64-bit.exe'
    if($reldata.browser_download_url) {
        Write-Debug ("Downloading from {0}" -f $reldata.browser_download_url)

        $OutputFile = Save-FileOnURL -URL $reldata.browser_download_url -OutputPath $InstallRepoPath
        #$downloadPath = Join-Path -Path $privdir\_down -ChildPath $release.name
        #Invoke-WebRequest -Uri $release.browser_download_url -UseBasicParsing -OutFile $downloadPath
        #Unblock-File -Path $downloadPath

        $GitSettngsDir = $PSScriptRoot
        if(-not $GitSettngsDir) {
            $GitSettngsDir = (Get-Location).Path
        }
        $GitInstallSettings = Join-Path -Path $GitSettngsDir -ChildPath "customizations\git_install.inf"


        Start-Process -FilePath $OutputFile `
        -ArgumentList "/VERYSILENT /LOADINF=$GitInstallSettings" `
        -NoNewWindow -Wait
    } else {
        Write-Warning ("No URL found")
    }
}

Function _Install-Python2 {
    [cmdletBinding()]
    Param(
    )

    # If -debug is set, change $DebugPreference so that output is a little less annoying.
    #    http://learn-powershell.net/2014/06/01/prevent-write-debug-from-bugging-you/
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }

    #############################################
    #
    # Python 2 for windows
    #
    #$DownloadURL="https://www.python.org/ftp/python/2.7.15/python-2.7.15.amd64.msi"
    $BasePythonDownloadURL = 'https://www.python.org/ftp/python'
    $LatestVersionHref = Invoke-WebRequest $BasePythonDownloadURL -UseBasicParsing | select -ExpandProperty Links | ? { $_.href -match '^2\.[0-9].*' } | ForEach-Object {
        [version]::Parse( $($_.href -replace "/","" ) ) | Add-Member -MemberType NoteProperty -name href -Value $_.href -PassThru
    } | sort -Property Major,Minor,Build,Revision -Descending | select -first 1 -ExpandProperty href

    $LatestVersionHref = $LatestVersionHref -replace "/",""

    # this is a bit unneccesary...
    $DownloadHref = Invoke-WebRequest -Uri ("{0}/{1}" -f $BasePythonDownloadURL,$LatestVersionHref) | select -ExpandProperty Links | ? {$_.href -match ('python-{0}.amd64.msi$' -f $LatestVersionHref) } | select -first 1 -ExpandProperty href
    $DownloadURL = "{0}/{1}/{2}" -f $BasePythonDownloadURL,$LatestVersionHref,$DownloadHref
    $LocalFileName=Save-FileOnURL -URL $DownloadURL -OutputPath $InstallRepoPath
    $InstallDir=$(Join-Path -Path $ToolsPath -ChildPath "Python2")

    Invoke-MSIFile -InstallFile $LocalFileName -MSIParameters ("TARGETDIR=`"{0}`"" -f $InstallDir)

    & $InstallDir\python.exe  -m pip install --upgrade pip

    $PythonScriptDir=Join-Path -Path $InstallDir -ChildPath "Scripts"

    # global packages
    "pylint","virtualenvwrapper","virtualenvwrapper-win" | ForEach-Object {
        & $PythonScriptDir\pip install $_
    }
}



_Disable-CertificateVerification

if(-not $env:AO_HOME) {
    $privdir=Read-Host 'privdir'
} else {
    $privdir=$env:AO_HOME
}


<#
_Install-GitForWindows -verbose -debug
#>

###########################
# tools to look into
#
# desktop ticker: http://www.battware.co.uk/desktopticker.htm
#
