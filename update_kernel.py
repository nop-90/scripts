#!/usr/bin/python
import urllib, requests, json, subprocess, select

json_file = json.loads(requests.get('https://www.kernel.org/releases.json').text)
latest_ver = json_file['latest_stable']['version']
current_ver = subprocess.Popen("uname -r | cut -d- -f1", shell=True, stdout=subprocess.PIPE)
current_ver = current_ver.communicate()[0].decode('utf-8').strip('\n')

major_ver_cur = current_ver.split('.')[0]
minor_ver_cur = current_ver.split('.')[1]
rev_cur = current_ver.split('.')[2]
major_ver_lat = latest_ver.split('.')[0]
minor_ver_lat = latest_ver.split('.')[1]
rev_lat = latest_ver.split('.')[2]

maj_min = major_ver_lat+minor_ver_lat

if major_ver_cur == major_ver_lat:
    if minor_ver_cur == minor_ver_lat:
        if rev_cur == rev_lat:
            print("Latest version, no need to updated")
        else:
            update_start()
    else:
        update_start()
else:
    print("Major update incoming, problems too. Sure you wanna update ?")
    res = read()
    if res == "Y" or res == "y":
        update_major_start()
    else:
        print("Aborting")

def update_major_start():
    print("Updating from version ",current_ver," to latest version ",latest_ver)
    kernel = urllib.URLOpener()
    kernel.retrieve('https://www.kernel.org/pub/linux/kernel/v4.x/linux-'+latest_ver+'.tar.xz','/usr/src/linux-'+latest_ver+'.tar.xz')
    shell = subprocess.Popen(['zsh'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    poll = select.poll()
    poll.register(shell.stdout.fileno(),select.POLLIN)

    # cd
    shell.stdin.write("cd /usr/src/")
    shell.stdin.flush()
    ready = poll.poll(500)
    
    # extract
    shell.stdin.write("tar -xvf linux-"+maj_min+".tar.xz")
    shell.stdin.flush()
    ready = poll.poll(25000)
    if ready:
       result = shell.stdout.readline()
       print(result)

    # cd
    shell.stdin.write("cd linux-"+maj_min)
    shell.stdin.flush()
    ready = poll.poll(500)

    # copy old config
    shell.stdin.write("cp ../linux/.config .")
    shell.stdin.flush()
    ready = poll.poll(2000)
    
    # make old config
    shell_make = subprocess.Popen(['terminator','-e','"cd /usr/src/linux-'+maj_min+'; make oldconfig; exit;"'], stdin=subprocess.PIPE)
    shell_make.wait()

    # make
    shell_make = subprocess.Popen(['terminator','-e','"cd /usr/src/linux-'+maj_min+'; make -j5; exit;"'], stdin=subprocess.PIPE)
    shell_make.wait()
    
    # rm old backup
    shell.stdin.write("rm -f /boot/vmlinuz.old")
    shell.stdin.flush()
    ready = poll.poll(500)

    # move current vmlinuz to backup
    shell.stdin.write("mv /boot/{vmlinuz"+major_ver_cur+",vmlinuz.old}")
    shell.stdin.flush()
    ready = poll.poll(500)

    # copy new vmlinuz to /boot

    # install new modules

    # make dkms deps

    # redo initramfs

    # rm old linux shortcut

    # add new linux shortcut
def update_start(): 
    print("Updating from version ",current_ver," to latest version ",latest_ver)
    kernel = urllib.URLOpener()
    kernel.retrieve('https://cdn.kernel.org/pub/linux/kernel/v4.x/incr/patch-'+major_ver_lat+'.'+minor_ver_lat+'.'+rev_cur+'-'+rev_lat+'.xz','/usr/src/linux')
    shell = subprocess.Popen(['zsh'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    poll = select.poll()
    poll.register(shell.stdout.fileno(),select.POLLIN)
