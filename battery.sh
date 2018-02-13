#rmmod nvidia_drm nvidia_modeset nvidia
#modprobe -r bbswitch
#modprobe bbswitch
if [[ $1 == "on" ]]; then
    iw dev wlp2s0 set power_save on
    echo "1-12" | sudo tee /sys/bus/usb/drivers/usb/unbind
    brightnessctl s 10%
    cpupower frequency-set -g powersave
else
    iw dev wlp2s0 set power_save off
    echo "1-12" | sudo tee /sys/bus/usb/drivers/usb/bind
    brightnessctl s 30%
    cpupower frequency-set -g performance
fi
