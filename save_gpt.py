import subprocess
import hashlib

def save_disk(file, dev):
    print("Saving ",dev," partition table")
    part_number = int(subprocess.Popen(["parted","-ms",dev,"print","|","tail","-1","|","cut","-b1"], stdout=subprocess.PIPE).communicate())
    count = part_number*128 + 1024
    subprocess.Popen(["dd","of="+file,"if="+dev,"bs=1","count="+str(count)], stdout=subprocess.PIPE)

def check_disk(file, dev):
    print("Checking integrity of disk GPT partition scheme ",dev)
    part_number = int(subprocess.Popen(["parted","-ms",dev,"print","|","tail","-1","|","cut","-b1"], stdout=subprocess.PIPE).communicate())
    count = part_number*128 + 1024
    subprocess.Popen(["dd","of=/tmp/disk","if="+dev,"bs=1","count="+str(count)], stdout=subprocess.PIPE)
    BLOCKSIZE = 65536
    hasher = hashlib.sha256()
    with open('/tmp/disk','rb') as orig:
        buf = orig.read(BLOCKSIZE)
        while len(buf) > 0:
            hasher.update(buf)
            bug = orig.read(BLOCKSIZE)

    signature_orig = hasher.hexdigest()

    hasher = hashlib.sha256()
    with open(file, 'rb') as file:
        buf = file.read(BLOCKSIZE)
        while len(buf) > 0:
            hasher.update(buf)
            bug = file.read(BLOCKSIZE)

    signature_file = hasher.hexdigest()

    if signature_orig == signature_file:
        print("Integrity check passed")
    else:
        print("Integrity check not correct")
    
def restore_disk(file, dev):
    print("Restoring ",dev," from ",file)
    print("Are you sure (Y or N) ?")
    choice = input()

    if choice = "Y" or choice == "y":
        part_number = int(subprocess.Popen(["parted","-ms",dev,"print","|","tail","-1","|","cut","-b1"], stdout=subprocess.PIPE).communicate())
        count = part_number*128 + 1024
        subprocess.Popen(["dd","of="+dev,"if="+file,"bs=1","count="+str(count)], stdout=subprocess.PIPE)

def list_disk():
    print("Partition list")
    list = subprocess.Popen(["parted",dev,"print"], stdout=subprocess.PIPE).communicate()
    print(list)

print("GPT partition table script")
print("1 - List partition from disk")
print("2 - Save disk")
print("3 - Restore disk")
print("4 - Integrity check")


