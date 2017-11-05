from Crypto.PublicKey import RSA
import subprocess
import shutil
import struct
import re
import os
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

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise RSAException('Modular inverse does not exist')
    else:
        return x % m

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

    def __init__(self, file_src, passphrase = None):
        if isinstance(file_src, str):
            if os.path.exists(file_src):
                self.file_src = file_src
                self.pk_content = open(self.file_src).read()
                self.init_privkey()
            else:
                raise PrivException("Private key file not found")
        elif isinstance(file_src, dict):
            if 'e' in file_src and 'n' in file_src and 'p' in file_src and 'q' in file_src:
                if isinstance(file_src['e'], int) and isinstance(file_src['p'], int) and \
                    isinstance(file_src['q'], int) and isinstance(file_src['n'], int):
                    self.pk_object = file_src
                    if passphrase != "":
                        self.passphrase = passphrase
                    if 'd' not in file_src:
                        try:
                            self.pk_object['d'] = modinv(self.pk_object['e'], self.getPhi())
                        except RSAException as e:
                            print(e.getMessage())
                else:
                    raise PrivException("A variable in the private key object is not a number")
            else:
                raise PrivException("Object is not a correct private key (must have e,p,q,n)")
        else:
            raise PrivException("Argument is not a file path or a private key object")

    def getPhi(self):
        return (self.pk_object['p']-1)*(self.pk_object['q']-1)

    def getKey(self):
        return self.pk_object

    def raiseExFunction(self):
        raise PrivException("Conversion from "+self.pk_type+" to "+input_key_type+" not supported")

    def convert(self, input_key_type):
        if input_key_type in self.key_type:
            getattr(self,self.pk_type+"_to_"+input_key_type,self.raiseExFunction)
        else:
            raise PrivException("Output format not supported")

    def init_privkey(self):
        header = self.pk_content.split('\n')[0]
        # PKCS1
        if header[0:31] == '-----BEGIN RSA PRIVATE KEY-----':
            self.pk_type = "pkcs1"
            self.pk_object = self.pkcs1_privkey_reading()
        # PKCS8
        elif header[0:37] == '-----BEGIN ENCRYPTED PRIVATE KEY-----'  or header[0:27]  == '-----BEGIN PRIVATE KEY-----':
            self.pk_type = "pkcs8"
            self.pk_object = self.pkcs8_privkey_reading()
        # OpenSSH
        elif header[0:35] == '-----BEGIN OPENSSH PRIVATE KEY-----':
            self.pk_type = "ssh"
            self.pk_object = self.ssh_privkey_reading()
        else:
            raise PrivException("Malformed header, is it really a RSA private key ?")

    def getByteSize(self):
        original_key = RSA.importKey(self.pk_content, self.passphrase)
        return original_key.bit_length

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
        return export_priv("pkcs8", converted_key)

    def ssh_to_pkcs1(self):
        converted_key = self.generate_privkey(self.pk_object['n'], self.pk_object['e'], self.pk_object['d'], self.pk_object['p'],
            self.pk_object['q'])
        return export("pkcs1", converted_key)

    def pkcs1_to_pkcs8(self):
        original_key = RSA.importKey(self.pk_content, self.passphrase)
        return export("pkcs8", original_key)

    def pkcs1_to_ssh(self):
        original_key = RSA.importKey(self.pk_content, self.passphrase)
        return export("ssh", original_key)

    def pkcs8_to_pkcs1(self):
        original_key = RSA.importKey(self.pk_content, self.passphrase)
        return export("pkcs1", converted_key)

    def pkcs8_to_ssh(self):
        original_key = RSA.importKey(self.pk_content, self.passphrase)
        return export("ssh", original_key)

    def export(self, format, key=None):
        export_key = ""
        if key != None:
            if format == "pkcs1":
                export_key = key.exportKey().decode('utf-8')
            elif format == "pkcs8":
                export_key = key.exportKey(pkcs=8).decode('utf-8')
            elif format == "ssh":
                export_key = key.exportKey(format="OpenSSH").decode('utf-8')
        else:
            key = self.generate_privkey(self.pk_object['n'], self.pk_object['e'], self.pk_object['d'], self.pk_object['p'], self.pk_object['q'])
            if format == "pkcs1":
                export_key = key.exportKey().decode('utf-8')
            elif format == "pkcs8":
                export_key = key.exportKey(pkcs=8).decode('utf-8')
            elif format == "ssh":
                export_key = key.exportKey(format="OpenSSH").decode('utf-8')
        return export_key

class PublicKey:
    file_src = ""
    pk_content = ""
    pk_object = ""
    pk_type = ""
    key_type = ['pkcs','ssh']

    def __init__(self, file_src):
        if isinstance(file_src, str):
            if os.path.exists(file_src):
                    self.file_src = file_src
                    self.pk_content = open(self.file_src).read()
                    self.init_pubkey()
            else:
                raise PubException("Public key file was not found")
        elif isinstance(file_src, dict):
            if 'e' in file_src and 'n' in file_src:
                self.pk_object = file_src
            else:
                raise PubException("Object is not a correct public key")
        else:
            raise PubException("Argument is not a file path or a public key object")

    def init_pubkey(self):
        header = self.pk_content.split('\n')[0]
        # PKCS1 and 8
        if header[0:26] == '-----BEGIN PUBLIC KEY-----' or header[0:30] == '-----BEGIN RSA PUBLIC KEY-----':
            self.pk_type = "pkcs"
            self.pk_object = self.pkcs_pubkey_reading()
        # OpenSSH
        elif header[0:7] == 'ssh-rsa':
            self.pk_type = "ssh"
            self.pk_object = self.ssh_pubkey_reading()
        else:
            raise PubException("Malformed header, is it really a RSA public key ?")

    def getKey(self):
        return self.pk_object

    def raiseExFunction():
        raise PubException("Conversion from "+self.pk_type+" to "+input_key_type+" not supported")

    def convert(self, input_key_type):
        if input_key_type in self.key_type:
            return getattr(self,self.pk_type+"_to_"+input_key_type,self.raiseExFunction)()
        else:
            raise PubException("Output format not supported")

    def getByteSize(self):
        original_key = RSA.importKey(self.pk_content, self.passphrase)
        return original_key.bit_length

    def pkcs_pubkey_reading(self):
        original_key = RSA.importKey(self.pk_content)
        return {"e":original_key.e,"n":original_key.n}

    def ssh_pubkey_reading(self):
        key_str = self.pk_content.split(None)
        pub_key = parse_DER(key_str[1])
        return pub_key

    def generate_pubkey(self,n,e):
        return RSA.construct((n,e))

    def ssh_to_pkcs(self):
        converted_key = self.generate_pubkey(self.pk_object['n'], self.pk_object['e'])
        return self.export("pkcs8", converted_key)

    def pkcs_to_ssh(self):
        original_key = RSA.importKey(self.pk_content)
        return self.export("ssh", original_key)

    def pkcs_to_pkcs(self):
        return self.pk_content

    def ssh_to_ssh(self):
        return self.pk_content

    def export(self, format, key=None):
        export_key = ""
        if key != None:
            if format == "pkcs":
                export_key = key.exportKey(pkcs=1).decode('utf-8')
            elif format == "ssh":
                export_key = key.exportKey(format="OpenSSH").decode('utf-8')
            else:
                raise PubException("Format not supported for public key")
        else:
            key = self.generate_pubkey(self.pk_object['n'], self.pk_object['e'])
            if format == "pkcs":
                export_key = key.exportKey(pkcs=1).decode('utf-8')
            elif format == "ssh":
                export_key = key.exportKey(format="OpenSSH").decode('utf-8')
            else:
                raise PubException("Format not supported for public key")
        return export_key
