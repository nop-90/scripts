#!/bin/bash
echo "Outil de mise à jour du noyau - Paramètres : update_kernel.sh \"nouvelle version du noyau\""
echo "Démarrer en droit root"
cd /usr/src/linux
if [ -z $1 ]
then
	echo "Nouvelle version du noyau :"
	read version
else
	version=$1
fi
chars=$(echo ${#version})
if [ $chars -eq 6 ]
then 
	ver=$(echo $version | cut -c6-6)
	old_kernel=$(uname -r | cut -c1-6)
elif [ $chars -eq 5 ]
then
	ver=$(echo $version | cut -c5-5)
	old_kernel=$(uname -r | cut -c1-5)
elif [ $chars -eq 4 ]
then
	ver=0
	old_kernel=$(uname -r | cut -c1-4)
else
	ver=$(echo $version | cut -c6-6)
	old_kernel=$(uname -r | cut -c1-6)
fi
if [ $ver -eq 1 ] || [ $ver -eq 0 ]
then
	wget https://www.kernel.org/pub/linux/kernel/v4.x/patch-$version.xz
	patch_bz2="patch-$version"
else
	let "a=ver-1"
	if [ $chars -eq 5 ] 
	then
		sup_ver=$(echo $version | cut -c1-3)
	else
		sup_ver=$(echo $version | cut -c1-4)
	fi
	patch_ver="$sup_ver.$a-$ver"
	wget https://www.kernel.org/pub/linux/kernel/v4.x/incr/patch-$patch_ver.xz
	patch_bz2="patch-$patch_ver"
fi
unxz $patch_bz2.xz
patch -p1 < $patch_bz2
make -j5
make modules_install
rm /boot/vmlinuz.old
mv /boot/vmlinuz4 /boot/vmlinuz.old
cp arch/x86_64/boot/bzImage /boot/vmlinuz4
echo "Mise à jour du fichier grub.cfg"
sed -i -e "s/$old_kernel/$version/g" /boot/grub/grub.cfg
dkms install -m nvidia/370.28 -k ${version}-nop-90
dkms install -m bbswitch/0.8 -k ${version}-nop-90
rm /boot/grub/grub2.cfg
cp /boot/grub/grub.cfg /boot/grub/grub2.cfg
#if [ -z $2 ]
#then
#	echo "Compilation des modules supplémentaires"
#	dkms autoinstall -k $version-arch
#	catalyst_build_module $version-arch
#	echo "Recompilation de l'initrd et création des liens pour les extra modules"
#	rm /usr/lib/modules/extramodules-$sup_ver-arch/version
#	echo "$version-arch" >> /usr/lib/modules/extramodules-$sup_ver-arch/version
#	rm /usr/lib/modules/extramodules-$sup_ver-arch/fglrx.ko*
#	ln -s /usr/lib/modules/extramodules-$sup_ver-arch/ /usr/lib/modules/$version-arch/extramodules
#	mkinitcpio -k $version-arch -g /boot/initrd3.img
#else
#	sup_ver=$(uname -r | cut -c1-4)
#	echo "Compilation manuelle des modules externes"
#	rm /usr/lib/modules/extramodules-$sup_ver-arch/version
#	echo "$version-arch" >> /usr/lib/modules/extramodules-$sup_ver-arch/version
#	rm /usr/lib/modules/extramodules-$sup_ver-arch/fglrx.ko*
#	ln -s /usr/lib/modules/extramodules-$sup_ver-arch/ /usr/lib/modules/$version-arch/extramodules
#	catalyst_build_module $version-arch
#	mkinitcpio -k $version-arch -g /boot/initrd3.img
#fi
