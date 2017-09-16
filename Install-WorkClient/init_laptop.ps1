Function New-DirectoryIfNotExists($dirname) {

    if(-not $(Test-Path -Path $dirname)) { mkdir $dirname }
}


Function Install-WorkClient() {
    [cmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    [string]$PrivDir
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




    New-DirectoryIfNotExists -dirname $privdir
    $subdirs = @("_down","install_logs","scheduled_scripts","tools")
    $subdirs | ForEach-Object {
        New-DirectoryIfNotExists -dirname $(Join-Path -Path $privdir -ChildPath $_) 
    }

    update-help

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


    <#
    $feature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V
    if(-not $($feature.State -eq "Enabled") ) {
        Enable-WindowsOptionalFeature -Online  -FeatureName Microsoft-Hyper-V -All
        $RebootIt = $true
    }
    #>


    $package = Get-Package -ProviderName msi -Name "Google Chrome" -ErrorAction Continue
    if(-not $package) {
        & msiexec /i $privdir\_down\googlechromestandaloneenterprise64.msi /passive /log $privdir\install_logs\chrome_install.log
    }

    # RSAT for windows 10. KB2693643
    $rsat = get-hotfix -Id KB2693643
    if(-not $rsat) {
        Start-Process -FilePath C:\Windows\System32\wusa.exe -ArgumentList "$privdir\_down\WindowsTH-RSAT_WS2016-x64.msu /quiet /norestart /log:$privdir\install_logs\rsat_install.log" -WindowStyle Hidden -Wait
        $RebootIt = $true
    }

    Remove-Item -Path HKCU:\SOFTWARE\Policies\Google -Force -Recurse 

    $SChedTask = Get-ScheduledTask -TaskName "Logon script" -TaskPath "\"

    if(-not $SChedTask) {
        $SchedTrigger = New-ScheduledTaskTrigger -AtLogOn
        $SchedAction = New-ScheduledTaskAction -Execute powershell.exe -Argument "-NoLogo -NonInteractive -WindowStyle Hidden -ExecutionPolicy UnRestricted -File $privdir\scheduled_scripts\logon_script.ps1" -WorkingDirectory $privdir\scheduled_scripts\
        $SChedSettings = New-ScheduledTaskSettingsSet
        $SChedTask = New-ScheduledTask -Action $SchedAction -Trigger $SchedTrigger -Description "Custom logon script" -Settings $SChedSettings
        Register-ScheduledTask -TaskName "Logon script" -InputObject $SChedTask -TaskPath "\"
    }

    if($RebootIt) {
        Restart-Computer -Force
    }

    # enable developer mode for lInux subsystem
    New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock -Name AllowDevelopmentWithoutDevLicense -PropertyType DWord -Value 1 -Force


    Invoke-WebRequest -Uri "https://download.sysinternals.com/files/SysinternalsSuite.zip" -OutFile $privdir\_down\sysinternals.zip
    Unblock-File -Path $privdir\_down\sysinternals.zip
    remove-Item -Path $(join-path -path $env:ProgramFiles -ChildPath "sysinternals")
    Expand-Archive -Path $privdir\_down\sysinternals.zip -DestinationPath $(join-path -path $env:ProgramFiles -ChildPath "sysinternals") -Force
    & "$(join-path -path $env:ProgramFiles -ChildPath "sysinternals")\procexp.exe" -accepteula



    Start-Process -FilePath C:\Windows\System32\cmd.exe -ArgumentList "/c `"lxrun /install /y`"" -WindowStyle Normal -Wait
    # initially set default user as root
    Start-Process -FilePath C:\Windows\System32\cmd.exe -ArgumentList "/c `"lxrun /setdefaultuser root /y`"" -WindowStyle Normal -Wait



    # WSL path 
    # ii C:\Users\aos019\AppData\Local\lxss\rootfs\etc\default
    # C:\Users\aos019\AppData\Local\lxss\rootfs\etc\default
    # to set locale
    # sudo update-locale LANG=en_US.UTF8
    # cat /etc/default/locale
    # LANG=en_US.UTF8

    # WSL set $env:computername to 127.0.0.1 in /etc/hosts


$WSLInitPrivScript=@'
#!/bin/sh
/usr/sbin/update-locale LANG=en_US.UTF8
# python-dev for pip
# libffi-dev for ansible
# libssl-dev for ansible
apt-get --assume-yes install vim git tmux python-pip python-dev libffi-dev libssl-dev
pip install ansible
#boto is needed by ec2 module
pip install boto
# github3.py needed by github_release module
pip install github2 github3.py
updatedb
'@

    $WSLInitPrivScript.Replace("`r`n","`n") | Set-Content -Path $privdir\init_bash.sh -Encoding UTF8

    Start-Process -FilePath C:\Windows\System32\bash.exe -ArgumentList "-c `"sh /mnt/$($PrivDir.Replace(':','').Replace('\','/'))/init_bash.sh`"" -WindowStyle Normal -Wait



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

    
    ##############################


    # nuget
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -force

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
        ,@{ RegKey = "hidedriveswithnomedia"; Value = 0 }
        ,@{ RegKey = "hidemergeconflicts"; Value = 0 }
        ,@{ RegKey = "autocheckselect"; Value = 0 }
    )
     
    $ExplorerRegData | ForEach-Object {
        Write-Warning "Setting $($_.RegKey) to $($_.Value)"
        Set-ItemProperty -Path $ExplorerRegPath -Name $_.REgKey -Value $_.Value
    }

    Stop-Process -processname explorer


    # might need a reboot
    Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PrecisionTouchPad' -Name RightClickZoneEnabled -Value 0


    # beyond compare
    Invoke-WebRequest -Uri https://www.scootersoftware.com/BCompare-3.3.13.18981.exe -UseBasicParsing -OutFile $privdir\_down\BCompare-3.3.13.18981.exe
    Unblock-File -Path $privdir\_down\BCompare-3.3.13.18981.exe



    ############################
    # vagrant
    # https://www.vagrantup.com/downloads.html

    Invoke-WebRequest -Uri https://releases.hashicorp.com/vagrant/2.0.0/vagrant_2.0.0_x86_64.msi -UseBasicParsing -OutFile $privdir\_down\vagrant_2.0.0_x86_64.msi
    Unblock-File -Path $privdir\_down\vagrant_2.0.0_x86_64.msi


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

    #>
}

$dir = Read-Host -Prompt "Privdir"

# Install-WorkClient -PrivDir $dir

