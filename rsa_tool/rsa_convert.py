from Crypto.PublicKey import RSA
import subprocess
import shutil
import struct
import re
from base64 import b64decode

def pkcs1_privkey_reading(file_src, passphrase=None):
    original_key = RSA.importKey(open(file_src).read(), passphrase)
    return {"e":original_key.e,"d":original_key.d,"n":original_key.n,"p":original_key.p,
            "q":original_key.q}

def pkcs8_privkey_reading(file_src, passphrase=None):
    original_key = RSA.importKey(open(file_src).read(), passphrase)
    return {"e":original_key.e,"d":original_key.d,"n":original_key.n,"p":original_key.p,
            "q":original_key.q}

def ssh_privkey_reading(file_src, passphrase=None):
    original_key = open(file_src,'r').read()
    header = original_key.split('\n')[0]
    private_key = None
    if re.search('-----BEGIN\sOPENSSH',header) != None:
        # OpenSSL doesn't read new OpenSSH format
        print("Warning : This programs writes an unencrypted copy of the private key in /tmp folder and shreds it immediately after.\nConfirm this action (Y or N) : ", end="")
        confirm = input()
        if confirm == "y" or confirm == "Y":
            shutil.copy(file_src,'/tmp/tempkey')
            if passphrase != None:
                remove_pass = subprocess.Popen(['ssh-keygen','-p','-P',passphrase,'-N','','-f','/tmp/tempkey'], stdout=subprocess.PIPE)
            else:
                remove_pass = subprocess.Popen(['ssh-keygen','-p','-P','','-N','','-f','/tmp/tempkey'], stdout=subprocess.PIPE)

            remove_pass.wait()
            private_key = RSA.importKey(open('/tmp/tempkey').read())
            remove_temp_key = subprocess.Popen(['shred','-n','10','-z','-u','/tmp/tempkey'], stdout=subprocess.PIPE)
        else:
            print("Aborting script.")
            exit()
    elif passphrase != None:
        # AES-128-CBC supported only by pyCrypto 2.7 and newer
        private_key = RSA.importKey(open(file_src).read(),passphrase)
    else:
        private_key = RSA.importKey(open(file_src).read())

    return {"e":private_key.e, "d":private_key.d, "n":private_key.n, "p":private_key.p, "q":private_key.q}

def pkcs8_pubkey_reading(file_src):
    # Too much key formats
    # https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem
    pub_key = []
    with open(file_src, 'r') as rsa:
        key_str = rsa.read().split('\n')
        if re.search("-----BEGIN PUBLIC KEY-----",key_str[0]):
            ssh_key_format = subprocess.Popen(['ssh-keygen','-i','-m','PKCS8','-f',file_src],
                    stdout=subprocess.PIPE).communicate()
            pub_key = parse_DER(ssh_key_format[0].split(None)[1])
        else:
            print("Not a PKCS#8 key, quitting...")
            exit()

    return pub_key

def parse_DER(der):
    # From https://telliott99.blogspot.fr/2011/08/dissecting-rsa-keys-in-python.html
    keydata = b64decode(der)

    parts = []
    while keydata:
        dlen = struct.unpack('>I',keydata[:4])[0]
        data, keydata = keydata[4:dlen+4], keydata[4+dlen:]
        parts.append(data)

    e = eval('0x' + ''.join(['%02X' % x for x in parts[1]]))
    n = eval('0x' + ''.join(['%02X' % x for x in parts[2]]))
    return {"e":e, "n":n}

def ssh_pubkey_reading(file_src):
    pub_key = []
    with open(file_src, 'r') as rsa:
        key_str = rsa.read().split(None)
        
        if key_str[0] != "ssh-rsa":
            print("Not an ssh-rsa key, quitting...")
            exit()
        
        pub_key = parse_DER(key_str[1])

    return pub_key

def generate_privkey(n,e,d,p,q):
    return RSA.construct((n,e,d,p,q))

def generate_pubkey(n,e):
    return RSA.construct((n,e))

def pub_ssh_to_pkcs8(file_src):
    pub_numbers = ssh_pubkey_reading(file_src)
    converted_key = generate_pubkey(pub_numbers['n'], pub_numbers['e'])
    return  export_pub(converted_key, "PCKS8")

def priv_ssh_to_pkcs8(file_src, passphrase = None):
    priv_numbers = ssh_privkey_reading(file_src, passphrase)
    converted_key = generate_privkey(priv_numbers['n'], priv_numbers['e'], priv_numbers['d'], priv_numbers['p'],
            priv_numbers['q'])
    return export_priv(converted_key, "PKCS8")

def priv_pkcs1_to_pkcs8(file_src, passphrase=None):
    original_key = RSA.importKey(open(file_src).read(), passphrase)
    return export_priv(original_key, "PKCS8")

def priv_pkcs1_to_ssh(file_src, passphrase=None):
    original_key = RSA.importKey(open(file_src).read(), passphrase)
    return export_priv(original_key, "SSH")

def priv_pkcs8_to_pkcs1(file_src, passphrase=None):
    original_key = RSA.importKey(open(file_src).read(), passphrase)
    return export_priv(converted_key, "PKCS1")

def priv_ssh_to_pkcs1(file_src, passphrase=None):
    priv_numbers = ssh_privkey_reading(file_src, passphrase)
    converted_key = generate_privkey(priv_numbers['n'], priv_numbers['e'], priv_numbers['d'], priv_numbers['p'],
        priv_numbers['q'])
    return export_priv(converted_key, "PKCS1")

def priv_pkcs8_to_ssh(file_src, passphrase=None):
    original_key = RSA.importKey(open(file_src).read(), passphrase)
    return export_priv(original_key, "SSH")

def pub_pkcs8_to_ssh(file_src):
    original_key = RSA.importKey(open(file_src).read(), passphrase)
    return export_priv(original_key, "SSH")

def export_priv(key, format):
    export_key = ""
    if format == "PKCS1":
        export_key = key.exportKey()
    elif format == "PKCS8":
        export_key = key.exportKey(pkcs=8)
    elif format == "SSH":
        export_key = key.exportKey(format="OpenSSH")
    return export_key

def export_pub(key, format):
    export_key = ""
    if format == "PKCS8":
        export_key = key.exportKey(pkcs=8)
    elif format == "SSH":
        export_key = key.exportKey(format="OpenSSH")
    return export_key

