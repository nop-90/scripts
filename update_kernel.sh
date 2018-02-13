#!/bin/bash
echo "Outil de mise à jour du noyau - Paramètres : update_kernel.sh \"nouvelle version du noyau\""
echo "Démarrer en droit root"
cd /usr/src/linux
current_ver=$(uname -r)
current_ver=${current_ver%-nop-90}
echo "Current version : $current_ver"
IFS='.' read -r -a current <<< $current_ver
cp .config ../config-${current[0]}.${current[1]}

if [ -z $1 ]; then
    echo "Updating to latest version"
    # Recherche de la dernière version
    latest_ver=$(python -c 'import json; import requests; print(json.loads(requests.get("https://www.kernel.org/releases.json").text)["latest_stable"]["version"])')
    if [ $latest_ver == "" ]; then
        exit
    fi
    echo "Latest version : $latest_ver"
    # Détermination de l'écart et téléchargement des patchs incrémentaux
    IFS='.' read -r -a latest <<< $latest_ver
    
    # Vars containing each part of version numbers
    maj_cur=${current[0]#0}
    med_cur=${current[1]#0}
    min_cur=${current[2]}
    maj_lat=${latest[0]#0}
    med_lat=${latest[1]#0}
    min_lat=${latest[2]}

    if [ $maj_lat -gt $maj_cur ] || [ $med_lat -gt $med_cur ]; then
        # Téléchargement de la nouvelle archive
        link="https://cdn.kernel.org/pub/linux/kernel/v$maj_lat.x/linux-$latest_ver.tar.xz"
		cd /usr/src
		echo "Downloading $latest_ver"
		wget $link
		tar -xvf linux-$latest_ver.tar.xz
		cd linux-$latest_ver
        rm /usr/src/linux
        ln -s /usr/src/linux-$latest_ver /usr/src/linux 
        latest_ver="$maj_lat.$med_lat.0"
		cp ../config-$maj_cur.$med_cur .config
		make oldconfig
    elif [ $min_lat -gt $min_cur ]; then
        # Téléchargement du patch demandé
        delta=$(($min_lat-$min_cur))
		for i in $(seq 1 1 $delta); do
            new=$(($min_cur+$i))
            if [ $new -eq 1 ]; then
                link="https://cdn.kernel.org/pub/linux/kernel/v$maj_cur.x/patch-$maj_cur.$med_cur.$new.xz"
                echo "Downloading patch-$maj_cur.$med_cur.$new.xz"
                wget $link
                unxz patch-$maj_cur.$med_cur.$new.xz
                echo "Minor patching to $maj_cur.$med_cur.$new"
                patch -p1 < patch-$maj_cur.$med_cur.$new
            else
                link="https://cdn.kernel.org/pub/linux/kernel/v$maj_cur.x/incr/patch-$maj_cur.$med_cur.$min_cur-$new.xz"
                echo "Downloading patch-$maj_cur.$med_cur.$min_cur-$new.xz"
                wget $link
                unxz patch-$maj_cur.$med_cur.$min_cur-$new.xz
                echo "Minor patching to $maj_cur.$med_cur.$new"
                patch -p1 < patch-$maj_cur.$med_cur.$min_cur-$new
            fi
		done
    else
        echo "No update available $latest_ver == $current_ver"
		exit
    fi

	# Building kernel
	make -j5
	make modules_install
    echo "Building DKMS modules"
	dkms install bbswitch/0.8 -k ${latest_ver}-nop-90
    echo "Copying new kernel/initrd"
	cryptsetup open /dev/sdb5 cryptboot
	mount /dev/mapper/cryptboot /boot
    mkinitcpio -k $latest_ver-nop-90 -g /boot/initrd4.img
	rm /boot/vmlinuz.old
	mv /boot/vmlinuz4 /boot/vmlinuz.old
	cp arch/x86_64/boot/bzImage /boot/vmlinuz4
	echo "Patching grub.cfg"
	sed -i -e "s/$current_ver/$latest_ver/g" /boot/grub/grub.cfg
	rm /boot/grub/grub2.cfg
	cp /boot/grub/grub.cfg /boot/grub/grub2.cfg
fi
