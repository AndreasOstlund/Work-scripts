
# find atom processes that has no child processe
$AtomProcs = Get-CimInstance -ClassName Win32_Process 
$TopLevelProcs = $AtomProcs | ? { $_.Name -eq "atom.exe" } | ForEach-Object {
    $proc = $_
    if(-not $($AtomProcs | ? { $_.ProcessId -eq $proc.ParentProcessId }) ) {
        $proc
    }
}

$TopLevelProcs

$HandleBin = "$env:AO_HOME\tools\sysinternals\handle64.exe"
$PathPattern = "M3Ops\\Multi-Tenant\\scripts\\"
& $HandleBin -a -p atom | Select-String -Pattern $PathPattern | `
    ForEach-Object {
        Write-Warning $_.Line.ToString()
        $AA=[regex]::split($_.Line.ToString(),'(.*): File.*')
        $Handle=$AA[1].replace(' ','')
        & $HandleBin -c $Handle -y -p $TopLevelProcs.ProcessId
    }


