qemu-system-x86_64 \
  -name "Windows10" \
  -machine type=q35,accel=kvm \
  -global ICH9-LPC.disable_s3=1 \
  -global ICH9-LPC.disable_s4=1 \
  -cpu host,kvm=off,hv_vapic,hv_relaxed,hv_spinlocks=0x1fff,hv_time,hv_vendor_id=12alphanum \
  -smp 8,sockets=1,cores=4,threads=2 \
  -m 3G \
  -balloon none \
  -rtc clock=host,base=localtime \
  -vnc 127.0.0.1:1 \
  -device qxl,bus=pcie.0,addr=1c.2 \
  -vga none \
  -serial none \
  -parallel none \
  -nographic \
  -usb \
  -device usb-tablet \
  -device ioh3420,bus=pcie.0,addr=1c.0,multifunction=on,port=1,chassis=1,id=root.1 \
  -device vfio-pci,host=01:00.0,bus=root.1,addr=00.0,x-pci-sub-device-id=4971,x-pci-sub-vendor-id=4318,multifunction=on,romfile=/home/nop-90/Documents/images/video.rom \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/ovmf/x64/OVMF_CODE.fd \
  -drive if=pflash,format=raw,file=/home/nop-90/Documents/images/WIN_VARS.fd \
  -boot menu=on \
  -boot order=c \
  -drive id=disk0,if=virtio,cache=none,format=raw,file=/var/lib/libvirt/images/Windows10VFIO.img \
  -drive file=/home/nop-90/Documents/images/Win10_1709_French_x64.iso,index=1,media=cdrom \
  -drive file=/home/nop-90/Documents/images/virtio-win-0.1.141.iso,index=2,media=cdrom \
