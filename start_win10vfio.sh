echo "Enable nvidia card for vfio"
echo "10de 139b" | sudo tee /sys/bus/pci/drivers/vfio-pci/new_id
echo "Start Windows 10"
virsh start win10-efi
sleep 12
xfreerdp /u:DUMMY /v:192.168.122.25:3389 /w:1600 /h:900 /bpp:32 +clipboard +fonts /gdi:hw /rfx /rfx-mode:video /sound:sys:pulse +menu-anims +window-drag
