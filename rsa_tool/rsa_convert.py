from Crypto.PublicKey import RSA
import subprocess
import shutil
import struct
import re
from base64 import b64decode

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

class RSAException(Exception):
    pass

class PrivException(RSAException):
    pass

class PubException(RSAException):
    pass

class PrivateKey:
    passphrase = None
    file_src = ""
    pk_type = ""
    pk_content = ""
    pk_object = {}
    key_type = ['ssh','pkcs1','pkcs8']

    def __init__(self, file_src, passphrase):
        if os.path.exists(file_src):
                self.file_src = file_src
                init_privkey()
                self.pk_content = open(self.file_src).read()
                if passphrase != "":
                    self.passphrase = passphrase
        else:
            raise IOError("Private key not found")

    def convert(self, input_key_type):
        if input_key_type in self.key_type:
            getattr(self,self.pk_type+"_to_"+input_key_type,lambda: raise PrivException("Conversion from "+self.pk_type+" to "+input_key_type+" not supported"))
        else:
            raise PrivException("Output format not supported")

    def init_privkey(self):
        header = self.pk_content.split('\n')[0]
        # PKCS1
        if header[0:31] == '-----BEGIN RSA PRIVATE KEY-----':
            self.pk_type = "pkcs1"
            self.pk_object = self.pkcs1_privkey_reading()
        # PKCS8
        elif header[0:37] == '-----BEGIN ENCRYPTED PRIVATE KEY-----':
            self.pk_type = "pkcs8"
            self.pk_object = self.pkcs8_privkey_reading()
        # OpenSSH
        elif header[0:35] == '-----BEGIN OPENSSH PRIVATE KEY-----'
            self.pk_type = "ssh"
            self.pk_object = self.ssh_privkey_reading()
        else:
            raise PrivException("Malformed header, is it really a RSA private key ?")

    def pkcs1_privkey_reading(self):
        original_key = RSA.importKey(self.pk_content, self.passphrase)
        return {"e":original_key.e,"d":original_key.d,"n":original_key.n,"p":original_key.p,
                "q":original_key.q}

    def pkcs8_privkey_reading(self):
        original_key = RSA.importKey(self.pk_content, self.passphrase)
        return {"e":original_key.e,"d":original_key.d,"n":original_key.n,"p":original_key.p,
                "q":original_key.q}

    def ssh_privkey_reading(self):
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
            raise PrivException("You refused to open the key")

        return {"e":private_key.e, "d":private_key.d, "n":private_key.n, "p":private_key.p, "q":private_key.q}

    def generate_privkey(self,n,e,d,p,q):
        return RSA.construct((n,e,d,p,q))

    def ssh_to_pkcs8(self):
        converted_key = self.generate_privkey(self.pk_object['n'], self.pk_object['e'], self.pk_object['d'], self.pk_object['p'],
                self.pk_object['q'])
        return export_priv(converted_key, "PKCS8")

    def ssh_to_pkcs1(self):
        converted_key = self.generate_privkey(self.pk_object['n'], self.pk_object['e'], self.pk_object['d'], self.pk_object['p'],
            self.pk_object['q'])
        return export_priv(converted_key, "PKCS1")

    def pkcs1_to_pkcs8(self):
        original_key = RSA.importKey(self.pk_content, self.passphrase)
        return export_priv(original_key, "PKCS8")

    def pkcs1_to_ssh(self):
        original_key = RSA.importKey(self.pk_content, self.passphrase)
        return export_priv(original_key, "SSH")

    def pkcs8_to_pkcs1(self):
        original_key = RSA.importKey(self.pk_content, self.passphrase)
        return export_priv(converted_key, "PKCS1")

    def pkcs8_to_ssh(self):
        original_key = RSA.importKey(self.pk_content, self.passphrase)
        return export_priv(original_key, "SSH")

    def export_priv(self, key, format):
        export_key = ""
        if format == "PKCS1":
            export_key = key.exportKey()
        elif format == "PKCS8":
            export_key = key.exportKey(pkcs=8)
        elif format == "SSH":
            export_key = key.exportKey(format="OpenSSH")
        return export_key

class PublicKey:
    file_src = ""
    pk_content = ""
    pk_object = ""
    pk_type = ""
    key_type = ['pkcs8','ssh']

    def __init__(self, file_src):
        if os.path.exists(file_src):
                self.file_src = file_src
                init_privkey()
                self.pk_content = open(self.file_src).read()
                if passphrase != "":
                    self.passphrase = passphrase
        else:
            raise IOError("Private key not found")

    def init_pubkey(self):
        header = self.pk_content.split('\n')[0]
        # PKCS8
        if header[0:26] == '-----BEGIN PUBLIC KEY-----':
            self.pk_type = "pkcs8"
            self.pk_object = self.pkcs8_privkey_reading()
        # OpenSSH
        elif header[0:7] == 'ssh-rsa'
            self.pk_type = "ssh"
            self.pk_object = self.ssh_privkey_reading()
        else:
            raise PrivException("Malformed header, is it really a RSA public key ?")

    def convert(self, input_key_type):
        if input_key_type in self.key_type:
            getattr(self,self.pk_type+"_to_"+input_key_type,lambda: raise PrivException("Conversion from "+self.pk_type+" to "+input_key_type+" not supported"))
        else:
            raise PrivException("Output format not supported")

    def pkcs8_pubkey_reading(self):
        # Too much key formats
        # https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem
        ssh_key_format = subprocess.Popen(['ssh-keygen','-i','-m','PKCS8','-f',self.file_src],
                stdout=subprocess.PIPE).communicate()
        pub_key = parse_DER(ssh_key_format[0].split(None)[1])
        return pub_key

    def ssh_pubkey_reading(self):
        key_str = self.pk_content.split(None)
        pub_key = parse_DER(key_str[1])
        return pub_key

    def generate_pubkey(self,n,e):
        return RSA.construct((n,e))

    def ssh_to_pkcs8(self):
        pub_numbers = self.ssh_pubkey_reading(self.file_src)
        converted_key = generate_pubkey(pub_numbers['n'], pub_numbers['e'])
        return  export_pub(converted_key, "PKCS8")

    def pkcs8_to_ssh(self):
        original_key = RSA.importKey(open(self.file_src).read(), passphrase)
        return export_priv(original_key, "SSH")

    def export_pub(self, key, format):
        export_key = ""
        if format == "PKCS8":
            export_key = key.exportKey(pkcs=8)
        elif format == "SSH":
            export_key = key.exportKey(format="OpenSSH")
        return export_key
