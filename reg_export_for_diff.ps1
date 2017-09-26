[cmdletBinding()]
Param(
    [string]$prefix
    ,[string]$exportdir
)

if(-not $prefix) { $prefix = Read-Host -Prompt "prefix" }
if(-not $exportdir) { $exportdir = Read-Host -Prompt "export to" }

$ts = (get-date).ToSTring("yyyyMMdd_HHmmss")
$ts

reg export HKLM\Software $(join-path -Path $exportdir -ChildPath "HKLM_${prefix}_${ts}.reg")
reg export HKCU\Software $(join-path -path $exportdir -childpath "HKCU_${prefix}_${ts}.reg")


