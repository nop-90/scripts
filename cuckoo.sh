echo "Start reporting docker database"
/home/nop-90/scripts/docker/cuckoo.sh
echo "Starting libvirt"
sudo /home/nop-90/scripts/services/start_libvirt.sh
echo "Starting virbr1 interface"
sudo virsh net-start vagrant-libvirt
sleep 1s
echo "Blocking output traffic on virbr1"
sudo nft insert rule filter output oif virbr1 reject
echo "Starting cuckoo daemon"
python2 /home/nop-90/Documents/sources/cuckoo/cuckoo.py&
echo "Starting web interface"
cd /home/nop-90/Documents/sources/cuckoo/web/
python2 manage.py runserver 127.0.0.1:8752&
firefox 127.0.0.1:8752
