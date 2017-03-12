#!/usr/bin/python3
from bs4 import BeautifulSoup
from base64 import b64decode
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA
import urllib.request
import sys
import re
import struct
import subprocess
import argparse
import shutil
import time

def main():
    #print(ssh_pubkey_reading('/home/nop-90/.ssh/id_rsa.pub'))
    #print(pkcs8_pubkey_reading('/tmp/pub.pem'))
    print(ssh_privkey_reading('/home/nop-90/.ssh/id_rsa_test'))
    parser = argparse.ArgumentParser()
    parser.add_argument('--pubin', help="input public key file")
    parser.add_argument('--hexpair', action="store_true", help="use hex-pair format in output")
    parser.add_argument('--hex', action="store_true", help="use raw hex format in output")
    parser.add_argument('--privin', help="input private key file")
    parser.add_argument('--inform', help="input key format", choices=["PCKS8","SSH","PCKS1"])
    parser.add_argument('--outform', help="output key format", choices=["PCKS8","SSH","PCKS1"])
    parser.add_argument('-m','--modulus', action="store_true", help="print modulus from key")
    parser.add_argument('-e','--exponant', action="store_true", help="print exponant from key")
    parser.add_argument('-p','--prime1', help="first prime number")
    parser.add_argument('-q','--prime2', help="second prime number")
    parser.add_argument('-ei', '--exponant-in', help="input public exponant number")
    parser.add_argument('-mi', '--modulus-in', help="input modulus number")
    parser.add_argument('-di','--decipher-in', help="input private exponant number")
    parser.add_argument('-c', '--cipher', choices=['path','text'], help="cipher data with provided data (raw numbers or public key)")
    parser.add_argument('-d', '--decipher', choices=['path','text'], help="decipher data with provided data (raw numbers or private key)")
    parser.add_argument('-b', '--bytes-len', help="get bit length of provided key (raw numbers or key file)")
    parser.add_argument('--random', type=int,  help="get random prime number with given bit size")
    parser.add_argument('--factor', help="factor number with factordb.com (if possible)")
    parser.add_argument('-g','--generate', action="store_true", help="generate key from provided numbers")
    args = parser.parse_args()

def generate_privkey(e,d,n,p,q):
    return RSA.construct((n,e,d,p,q))

def generate_pubkey(e,n):
    return RSA.construct((n,e))

def export_priv(key, format):
    export_key = ""
    if format == "PKCS1":
        export_key = key.exportKey()
    elif format == "PCKS8":
        export_key = key.exportKey(pcks=8)
    elif format == "SSH":
        export_key = key.exportKey(format="OpenSSH")
    return export_key

def export_pub(key, format):
    export_key = ""
    if format == "PKCS1":
        export_key = key.exportKey()
    elif format == "SSH":
        export_key = key.exportKey(format="OpenSSH")
    return export_key

def get_phi(p, q):
    return (p-1)*(q-1)

def pcks8_privkey_reading(file_src):
    original_key = RSA.importKey(open(file_src).read())
    return [original_key.keydata.e,original_key.keydata.d]

def ssh_privkey_reading(file_src, passphrase=None):
    original_key = open(file_src,'r').read()
    header = original_key.split('\n')[0]
    private_key = None
    if re.search('-----BEGIN\sOPENSSH',header) != None:
        # OpenSSL doesn't read new OpenSSH format
        print("Warning : This programs writes an unencrypted copy of the private key in /tmp folder and shreds it immediately after. \n Confirm this action (Y or N).")
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

    return [private_key.e, private_key.d, private_key.n, private_key.p, private_key.q]

def get_bytes_size(i):
    return i.bit_length

def get_prime(bits):
    prime = int(subprocess.Popen(['openssl','prime','-generate','-bits',bits], stdout=subprocess.PIPE).communicate())
    return prime

def encrypt(data,e,n):
    key = RSA.construct((e,n))
    cipher = PCKS1_v1_5.new(key)
    # possible SHA to add
    message = cipher.encrypt(data)
    return message

def decrypt(data, e,d,n):
    key = RSA.construct((e,d,n))
    cipher = PKCS1_v1_5.new(key)
    # possible SHA to add
    message = cipher.decrypt(data)
    return message

def pub_pcks1_to_ssh(file_src):
    pub_numbers = pcks8_pubkey_reading(file_src)
    converted_key = generate_pubkey(pub_numbers[0], pub_numbers[1])
    return  export_pub(converted_key, "SSH")

def pub_ssh_to_pcks1(file_src):
    pub_numbers = ssh_pubkey_reading(file_src)
    converted_key = generate_pubkey(pub_numbers[0], pub_numbers[1])
    return  export_pub(converted_key, "PCKS1")

def priv_ssh_to_pcks8(file_src, passphrase = None):
    priv_numbers = ssh_privkey_reading(file_src, passphrase)
    converted_key = generate_privkey(priv_numbers[0], priv_numbers[1], priv_numbers[2], priv_numbers[3], priv_numbers[4])
    return export_priv(converted_key, "PKCS8")

def priv_pcks1_to_pcks8(file_src):
    original_key = RSA.importKey(open(file_src).read())
    return original_key.exportKey(pkcs=8)

def priv_ssh_to_pcks1(file_src):
    priv_numbers = ssh_privkey_reading(file_src, passphrase)
    converted_key = generate_privkey(priv_numbers[0], priv_numbers[1], priv_numbers[2], priv_numbers[3], priv_numbers[4])
    return export_priv(converted_key, "PKCS1")

def get_prime_factor(factoring):
    prime_factors = []
    with urllib.request.urlopen("http://factordb.com/index.php?query="+factoring) as req:
        html = BeautifulSoup(req.read(), "html.parser")
        td = html.findAll("table")[1].findAll('tr')[2].findAll('td')[2].findAll("a")

        index = 0
        for number in td:
            if index == 0:
                print("Source number : "+sys.argv[1])
            else:
                prime = number.find('font').get_text()
                if re.search("\^", prime):
                    base = int(prime.split('^')[0])
                    power = int(prime.split('^')[1])
                    for i in range(0, power):
                        prime_factors.append(base)
                else:
                    prime_factors.append(int(prime))
            index += 1
    return prime_factors

def pkcs8_pubkey_reading(file_src):
    # Too much key formats. It's Obama's fault. Sad!
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
    return [e, n]

def ssh_pubkey_reading(file_src):
    pub_key = []
    with open(file_src, 'r') as rsa:
        key_str = rsa.read().split(None)
        
        if key_str[0] != "ssh-rsa":
            print("Not an ssh-rsa key, quitting...")
            exit()
        
        pub_key = parse_DER(key_str[1])

    return pub_key

if __name__ == "__main__":
    main()

