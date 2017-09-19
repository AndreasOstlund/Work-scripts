$prefix = Read-Host -Prompt "prefix"
$exportdir = Read-Host -Prompt "export to"

$ts = (get-date).ToSTring("yyyyMMdd_HHmmss")
$ts

reg export HKLM\Software $(join-path -Path $exportdir -ChildPath "HKLM_${prefix}_${ts}")
reg export HKCU\Software $(join-path -path $exportdir -childpath "HKCU_${prefix}_${ts}")


