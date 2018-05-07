$vboxmanage='C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
$vmbasedir = "c:\ao\VMs\machines"


$VMName = "devclient"
$isopath = "C:\AO\VMs\sources\Fedora-Workstation-netinst-x86_64-27-1.6.iso"

$vmdir = Join-Path -Path $vmbasedir -ChildPath "$VMName"
mkdir $vmdir

$vdiskpath = Join-Path -Path $vmdir -ChildPath "${VMName}.vdi"


& $vboxmanage createhd --filename $vdiskpath --size 16384
& $vboxmanage list ostypes

& $vboxmanage createvm --name $VMName --basefolder $vmbasedir --ostype Fedora_64 --register
& $vboxmanage storagectl $VMName --name "SATA controller" --add sata --controller IntelAHCI
& $vboxmanage storageattach $VMName --storagectl "SATA controller" --port 0 --device 0 --type hdd --medium $vdiskpath

& $vboxmanage storagectl $VMName --name "IDE controller" --add ide
& $vboxmanage storageattach $VMName --storagectl "IDE controller" --port 0 --device 0 --type dvddrive --medium $isopath

& $vboxmanage modifyvm $VMName --cpus 2  --vram 64
& $vboxmanage modifyvm $VMName --ioapic on --memory 2048 --vram 128 --audio none --usb off
& $vboxmanage modifyvm $VMName --boot1 dvd --boot2 disk --boot3 none --boot4 none

