#!/usr/bin/python3
from bs4 import BeautifulSoup
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA
from Crypto.Cipher import AES
import urllib.request
import sys
import subprocess
import argparse
import time
import os.path
import getpass

from rsa_convert import *

def main():
    args()

def is_valid_file(parser, arg):
    if not os.path.exists(arg):
        parser.error("The file %s does not exist!" % arg)
    return arg

def args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pubin', action="store", help="input public key file", type=lambda x: is_valid_file(parser, x))
    parser.add_argument('--hexpair', action="store_true", help="use hex-pair format in output")
    parser.add_argument('--hex', action="store_true", help="use raw hex format in output")
    parser.add_argument('--privin', action="store", help="input private key file", type=lambda x: is_valid_file(parser, x))
    parser.add_argument('--inform', action="store", help="input key format", choices=["PKCS8","SSH","PKCS1"])
    parser.add_argument('--outform', action="store", help="output key format", choices=["PKCS8","SSH","PKCS1"])
    parser.add_argument('-m','--modulus', action="store_true", help="print modulus from key")
    parser.add_argument('-phi', action="store_true", help="print Phi number from key")
    parser.add_argument('-e','--exponant', action="store_true", help="print exponant from key")
    parser.add_argument('-p','--prime1', action="store_true", help="get first prime number")
    parser.add_argument('-q','--prime2', action="store_true", help="get second prime number")
    parser.add_argument('-ei', '--exponant-in', help="input public exponant number")
    parser.add_argument('-mi', '--modulus-in', help="input modulus number")
    parser.add_argument('-pei','--privexp-in', help="input private exponant number")
    parser.add_argument('-pi','--prime1-in', help="input first prime p")
    parser.add_argument('-qi','--prime2-in', help="input second prime q")
    parser.add_argument('-c', '--cipher', choices=['path','text'], help="cipher data with provided data (raw numbers or public key) with stdin or file input")
    parser.add_argument('-ci','--cipher-in', help="path or text to cipher")
    parser.add_argument('-co','--cipher-out', help="path of cipher output")
    parser.add_argument('-di','--decipher-in', help="path or text to decipher")
    parser.add_argument('-ct','--cipher-type', help="select type of cipher to use for encryption or decryption", choices=['RSA','AES'])
    parser.add_argument('-do','--decipher-out', help="path of decipher output")
    parser.add_argument('-d', '--decipher', choices=['path','text'], help="decipher data with provided data (raw numbers or private key) with stdin or file input")
    parser.add_argument('-b', '--bytes-len', help="get bit length of provided key (raw numbers or key file)")
    parser.add_argument('-w', '--weak-keys', help="detect weak keys")
    parser.add_argument('--random', type=int,  help="get random prime number with given bit size")
    parser.add_argument('--factor', help="factor modulus with factordb.com (if possible)")
    parser.add_argument('-g','--generate', action="store_true", help="generate key from provided numbers")
    args = parser.parse_args()

    if (args.modulus != False or args.exponant != False or args.prime1 != False or args.prime2 != False or args.phi != False) and args.exponant_in == None:
        if args.pubin != None and not args.privin:
            if not args.inform:
                print("No input format provided")

            key_data = load_pub(args.inform, args.pubin)
            if args.hexpair and not args.hex:
                if args.modulus:
                    print(int_to_hexpair(key_data['n']))
                elif args.exponant:
                    print(int_to_hexpair(key_data['e']))
                else:
                    print("This data doesn't exists in this file")
            elif not args.hexpair and args.hex:
                if args.modulus:
                    print(hex(key_data['n']))
                elif args.exponant:
                    print(hex(key_data['e']))
                else:
                    print("This data doesn't exists in this file")
            else:
                if args.modulus and not args.exponant:
                    print(key_data['n'])
                elif args.exponant and not args.modulus:
                    print(key_data['e'])
                else:
                    print("This data doesn't exists in this file")
        elif args.privin != None and not args.pubin:
            if not args.inform:
                print("No input format provided")

            passphrase = getpass.getpass("Input key passphrase (press enter if empty) : ")
            if passphrase == "":
                passphrase = None

            key_data = load_priv(args.inform, args.privin, passphrase)
            if args.hexpair and not args.hex:
                if args.modulus:
                    print(int_to_hexpair(key_data['n']))
                elif args.exponant:
                    print(int_to_hexpair(key_data['d']))
                elif args.phi:
                    print(int_to_hexpair(get_phi(key_data['p'],key_data['q'])))
                elif args.prime1:
                    print(int_to_hexpair(key_data['p']))
                elif args.prime2:
                    print(int_to_hexpair(key_data['q']))
                else:
                    print("This data doesn't exists in this file")
            elif not args.hexpair and args.hex:
                if args.modulus:
                    print(hex(key_data['n']))
                elif args.exponant:
                    print(hex(key_data['d']))
                elif args.phi:
                    print(hex(get_phi(key_data['p'],key_data['q'])))
                elif args.prime1:
                    print(hex(key_data['p']))
                elif args.prime2:
                    print(hex(key_data['q']))
                else:
                    print("This data doesn't exists in this file")
            else:
                if args.modulus and not args.exponant:
                    print(key_data['n'])
                elif args.exponant and not args.modulus:
                    print(key_data['d'])
                elif args.phi:
                    print(get_phi(key_data['p'],key_data['q']))
                elif args.prime1:
                    print(key_data['p'])
                elif args.prime2:
                    print(key_data['q'])
                else:
                    print("This data doesn't exists in this file")
        elif args.pubin != None and args.privin != None:
            print("Cannot use public key and private key input in the same time")
        else:
            print("No input key provided")
    elif args.outform != None and args.inform != None:
        if args.pubin != None and not args.privin:
            if not args.inform:
                print("No input format provided")

            print(convert(args.inform, args.outform, "pub", args.pubin))
        elif args.privin != None and not args.pubin:
            if not args.inform:
                print("No input format provided")

            passphrase = getpass.getpass("Input key passphrase (press enter if empty) : ")
            if passphrase == "":
                passphrase = None

            print(convert(args.inform, args.outform, "priv", args.privin, passphrase).decode('utf-8'))
        elif args.privin != None and args.pubin != None:
            print("Cannot use public key and private key input in the same time")
        else:
            print("No input key provided")
    elif args.exponant_in != None and args.outform != None:
        if args.decipher_in != None and args.prime1_in != None and args.prime2_in != None:
            if (args.hexpair and not args.hex) or (args.hex and not args.hexpair):
                exponant = int(args.exponant_in.replace(':',''),16)
                priv_exponant = int(args.decipher_in.replace(':',''),16)
                prime1 = int(args.prime1_in.replace(':',''),16)
                prime2 = int(args.prime2_in.replace(':',''),16)
                modulus = prime1*prime2
                key = generate_privkey(modulus, exponant, priv_exponant, prime1, prime2)
            else:
                key = generate_privkey(int(args.prime1)*int(args.prime2),int(args.exponant_in),int(args.decipher_in),int(args.prime1_in),int(args.prime2_in))
            print(export_priv(key, args.outform).decode('utf-8'))
        elif args.decipher_in == None and args.prime1_in == None and args.prime2_in == None and args.modulus_in != None and args.outform != "PKCS1":
            if (args.hexpair and not args.hex) or (args.hex and not args.hexpair):
                modulus = int(args.modulus_in.replace(':',''),16)
                exponant = int(args.exponant_in.replace(':',''),16)
                key = generate_pubkey(modulus, exponant)
            else:
                key = generate_pubkey(int(args.modulus_in), int(args.exponant_in))

            print(export_pub(key, args.outform).decode('utf-8'))
        else:
            print("Can't create key, missing arguments or incorrect output type")
            exit()
    elif args.cipher != None and args.decipher == None:
        if args.pubin != None and args.modulus_in == None and args.exponant_in == None and args.inform != None:
            if args.cipher == "path":
                if args.cipher_in != None and os.path.isfile(args.cipher_in):
                    key = load_pub(args.inform, args.pubin)
                    if args.cipher_type != None:
                        ciphered = encrypt(open(args.cipher_in,'r').read(), key['e'], key['n'])
                    else:
                        ciphered = encrypt(open(args.cipher_in,'r').read(), key['e'], key['n'], args.cipher_type)

                    if args.cipher_out != None:
                        output = open(args.cipher_out,"wb")
                        if args.cipher_type == "AES":
                            output.write(ciphered[0]+'|'+ciphered[1])
                        else:
                            output.write(ciphered)
                        output.close()
                    else:
                        print(ciphered)
                else:
                    print("Path for input data doesn't exists or is not specified with -ci option")
                    exit()
            elif args.cipher == "text":
                key = load_pub(args.inform, args.pubin)
                if args.cipher_in != None or sys.stdin != None:
                    if sys.stdin == None:
                        if args.cipher_type != None:
                            ciphered = encrypt(args.cipher_in, pub_exp, modulus, args.cipher_type)
                        else:
                            ciphered = encrypt(args.cipher_in, pub_exp, modulus)

                    elif args.cipher_in != None:
                        if args.cipher_type != None:
                            ciphered = encrypt(sys.stdin.read(), pub_exp, modulus, args.cipher_type)
                        else:
                            ciphered = encrypt(sys.stdin.read(), pub_exp, modulus)
                    else:
                        print("Input data not found, use -ci option or STDIN")
                        exit()
                else:
                    print("Input text not provided")
                    exit()

                if args.cipher_out != None:
                    output = open(args.cipher_out,"wb")
                    if args.cipher_type == "AES":
                        output.write(ciphered[0]+'|'+ciphered[1])
                    else:
                        output.write(ciphered)
                    output.close()
                else:
                    print(ciphered)
            else:
                print("Wrong option for cipher")
                exit()
        elif args.modulus_in != None and args.exponant_in != None and args.pubin == None and args.inform == None:
            if (args.hexpair and not args.hex) or (args.hex and not args.hexpair):
                pub_exp = int(args.exponant_in.replace(':',''),16)
                modulus = int(args.modulus_in.replace(':',''),16)
            else:
                pub_exp = int(args.exponant_in)
                modulus = int(args.modulus_in)

            if args.cipher == "path":
                if args.cipher_in != None and os.path.isfile(args.cipher_in):
                    if args.cipher_type != None:
                        ciphered = encrypt(args.cipher_in, pub_exp, modulus, args.cipher_type)
                    else:
                        ciphered = encrypt(args.cipher_in, pub_exp, modulus)

                    if args.cipher_out != None:
                        output = open(args.cipher_out,"wb")
                        if args.cipher_type == "AES":
                            output.write(ciphered[0]+'|'+ciphered[1])
                        else:
                            output.write(ciphered)
                        output.close()
                    else:
                        print(ciphered)
                else:
                    print("File doesn't exists or input path not provided")
                    exit()
            elif args.cipher == "text":
                if args.cipher_in != None or sys.stdin != None:
                    if sys.stdin == None:
                        if args.cipher_type != None:
                            ciphered = encrypt(args.cipher_in, pub_exp, modulus, args.cipher_type)
                        else:
                            ciphered = encrypt(args.cipher_in, pub_exp, modulus)

                    elif args.cipher_in != None:
                        if args.cipher_type != None:
                            ciphered = encrypt(sys.stdin.read(), pub_exp, modulus, args.cipher_type)
                        else:
                            ciphered = encrypt(sys.stdin.read(), pub_exp, modulus)
                    else:
                        print("Input data not found, use -ci option or STDIN")
                        exit()

                    if args.cipher_out != None:
                        output = open(args.cipher_out,"wb")
                        if args.cipher_type == "AES":
                            output.write(ciphered[0]+'|'+ciphered[1])
                        else:
                            output.write(ciphered)
                        output.close()
                    else:
                        print(ciphered)
                else:
                    print("Input text not provided")
                    exit()
            else:
                print("Wrong option for cipher")
                exit()
        else:
            print("Public key argument -pubin cannot be used with -mi or -ei or -inform argument missing")
    elif args.decipher != None and args.cipher == None:
        if args.privin != None and args.prime1_in == None and args.prime2_in == None and args.modulus_in == None and args.exponant_in == None and args.privexp_in == None and args.inform != None:
            if args.decipher == "path":
                if args.decipher_in != None and os.path.isfile(args.decipher_in):
                    key = load_priv(args.inform, args.privin)
                    deciphered = decrypt(open(args.decipher_in,'rb').read(), key['e'], key['d'], key['n'])
                    if args.decipher_out != None:
                        output = open(args.decipher_out,"wb")
                        output.write(deciphered)
                        output.close()
                    else:
                        print(deciphered)
                else:
                    print("Path doesn't exists or is not specified with -di option")
                    exit()
            elif args.decipher == "text":
                key = load_priv(args.inform, args.privin)
                if args.decipher_in != None:
                    if args.cipher_type != None:
                        deciphered = decrypt(args.decipher_in, key['e'], key['d'], key['n'], args.cipher_type)
                    else:
                        deciphered = decrypt(args.decipher_in, key['e'], key['d'], key['n'])

                elif sys.stdin != None:
                    if args.cipher_type != None:
                        deciphered = decrypt(sys.stdin.read(), key['e'], key['d'], key['n'], args.cipher_type)
                    else:
                        deciphered = decrypt(sys.stdin.read(), key['e'], key['d'], key['n'])

                else:
                    print("Input data not found, use -di option or STDIN")
                    exit()

                if args.decipher_out != None:
                    output = open(args.decipher_out,"wb")
                    output.write(deciphered)
                    output.close()
                else:
                    print(deciphered)
            else:
                print("Wrong option for cipher")
                exit()
        elif args.privin == None and args.inform == None and (args.modulus_in != None or (args.prime1_in != None and args.prime2 != None)) and args.exponant_in != None and args.decipher_in != None:
            # Integer options parsing
            if (args.hexpair and not args.hex) or (args.hex and not args.hexpair):
                pub_exp = int(args.exponant_in.replace(':',''),16)
                if args.modulus_in != None:
                    modulus = int(args.modulus_in.replace(':',''),16)
                else:
                    modulus = int(args.prime1_in.replace(':',''),16)*int(args.prime2_in.replace(':',''),16)
                priv_exp = int(args.privexp_in.replace(':',''),16)
            else:
                pub_exp = int(args.exponant_in)
                if args.modulus_in != None:
                    modulus = int(args.modulus_in)
                else:
                    modulus = int(args.prime1_in)*int(args.prime2_in)
                priv_exp = int(args.privexp_in)

            if args.decipher == "path":
                if args.decipher_in != None and os.path.isfile(args.decipher_in):
                    if args.cipher_type != None:
                        decipher = decrypt(args.decipher_in,pub_exp,priv_exp,modulus, args.cipher_type)
                    else:
                        decipher = decrypt(args.decipher_in,pub_exp,priv_exp,modulus)

                    if args.decipher_out != None:
                        output = open(args.decipher_out,"wb")
                        output.write(decipher)
                        output.close()
                    else:
                        print(decipher)
                else:
                    print("File doesn't exists or input path not provided")
                    exit()
            elif args.decipher == "text":
                if args.decipher_in != None:
                    if args.cipher_type != None:
                        decipher = decrypt(args.decipher_in,pub_exp,priv_exp,modulus, args.cipher_type)
                    else:
                        decipher = decrypt(args.decipher_in,pub_exp,priv_exp,modulus)

                    if args.decipher_out != None:
                        output = open(args.decipher_out,"wb")
                        output.write(decipher)
                        output.close()
                    else:
                        print(decipher)
                else:
                    print("Input text not provided")
                    exit()
            else:
                print("Wrong option for decipher")
                exit()
        else:
            print("Private key argument -privin cannot be used with -mi, -ei or -di")
            exit()
    elif args.random:
        print(get_prime(args.random))
    elif args.factor:
        print(get_prime_factor(args.factor))
    elif args.bytes_len:
        pass
    else:
        print("Unrecognized arguments or wrong argument combination")
   
def convert(inform, outform, type, file_src, passphrase=None):
    converted = ""
    if inform == "PKCS1":
        if outform == "PKCS8":
            if type == "priv":
                converted = priv_pkcs1_to_pkcs8(file_src, passphrase)
            else:
                print("Can't convert public key with PKCS1 format (it doesn't exists)")
        elif outform == "SSH":
            if type == "priv":
                converted = priv_pkcs1_to_ssh(file_src, passphrase)
            else:
                print("Can't convert public key with PKCS1 format (it doesn't exists)")
        elif outform == "PKCS1":
            print("Input and output format are equals. Not doing anything")
        else:
            print("Unrecognized output format")
    elif inform == "PKCS8":
        if outform == "PKCS1":
            if type == "priv":
                converted = priv_pkcs8_to_pkcs1(file_src, passphrase)
            else:
                print("Can't convert public key to PKCS1 format (it doesn't exists)")
        elif outform == "SSH":
            if type == "priv":
                converted = priv_pkcs8_to_ssh(file_src, passphrase)
            else:
                converted = pub_pkcs8_to_ssh(file_src)
        elif outform == "PKCS8":
            print("Input and output format are equals. Not doing anything")
        else:
            print("Unrecognized output format")
    elif inform == "SSH":
        if outform == "PKCS8":
            if type == "priv":
                converted = priv_ssh_to_pkcs8(file_src, passphrase)
            else:
                converted = pub_ssh_to_pkcs8(file_src)
        elif outform == "PKCS1":
            if type == "priv":
                converted = priv_ssh_to_pkcs1(file_src, passphrase)
            else:
                print("Can't convert public key to PKCS1 format (it doesn't exists)")
        elif outform == "SSH":
            print("Input and output format are equals. Not doing anything")
        else:
            print("Unrecognized output format")
    else:
        print("Unrecognized input format")

    return converted

def is_prime(num):
    isPrime = True
    for i in range(1,isPrime):
        if num % i != 0:
            isPrime = False

    return isPrime

def int_to_hexpair(number):
    hexdata = ""
    number = str(hex(number))
    if len(number) % 2 == 0:
        l = 0
        i = 2
        while i < len(number):
            if l == 2:
                hexdata += ":"
                l = 0
            else:
                hexdata += str(number)[i:i+1]
                l += 1
                i += 1
    else:
        l = 0
        i = 2
        while i < len(number):
            if l == 2:
                hexdata += ":"
                l = 0
            elif l == 0 and i == 2:
                hexdata += "0"+str(number)[i:i+1]+":"
                l = 0
                i += 1
            else:
                hexdata += str(number)[i:i+1]
                l += 1
                i += 1
    return hexdata

def load_pub(format, src):
    key = ""
    if format == "PKCS8":
        key = pkcs8_pubkey_reading(src)
    elif format == "SSH":
        key = ssh_pubkey_reading(src)
    elif format == "PKCS1":
        print("Can't use PKCS1 format for public key")
        exit()
    else:
        print("Unrecognised format")
        exit()
    return key

def load_priv(format, src, passphrase=None):
    key = ""
    if format == "PKCS8":
        key = pkcs8_privkey_reading(src, passphrase)
    elif format == "SSH":
        key = ssh_privkey_reading(src, passphrase)
    elif format == "PKCS1":
        key = pkcs1_privkey_reading(src, passphrase)
    else:
        print("Unrecognised format")
        exit()
    return key

def get_phi(p, q):
    return (p-1)*(q-1)

def get_bytes_size(i):
    return i.bit_length

def get_prime(bits):
    prime = int(subprocess.Popen(['openssl','prime','-generate','-bits',bits], stdout=subprocess.PIPE).communicate())
    return prime

def encrypt(data,e,n,cipher):
    key = RSA.construct((n,e))
    cipher = PKCS1_v1_5.new(key)

    if cipher == 'RSA':
        try:
            message = cipher.encrypt(data.encode('utf-8'))
        except ValueError as e:
            print("Your key size is too small to encode this text with RSA (try increasing the modulus length)")
        return ':'.join([hex(int(msg)).replace('0x','') for msg in message])
    elif cipher == 'AES':
        aeskey = Random.new().read(24)
        iv = Random.new().read(AES.block_size)
        cipher_aes = AES.new(aeskey, AES.MODE_CBC, iv)
        msg = iv + cipher_aes.encrypt(data)

        random_gen = Random.new().read
        ciphertext = cipher.encrypt(aeskey)
        return [':'.join([hex(int(cipherbit)).replace('0x','') for bit in ciphertext]),':'.join([hex(int(text_bit)).replace('0x','') for text_bit in msg])]
    else:
        print(str(cipher)+" is not supported")

def decrypt(data,e,d,n,cipher):
    key = RSA.construct((n,d,e))
    cipher = PKCS1_v1_5.new(key)

    hex_string = data.split(':')
    decrypt = b''
    decrypt_aes_key = b''
    decrypt_iv = b''
    if cipher == "RSA":
        for hex in hex_string:
            decrypt += bytes([int(hex,16)])
        message = cipher.decrypt(decrypt, -1)
        return message
    elif cipher == "AES":
        data = data.split('|')
        hex_string_key = data[0].split(':')
        for hex in hex_string_key:
            decrypt_aes_key += bytes([int(hex,16)])
        aeskey = cipher.decrypt(decrypt_aes_key, -1)

        hex_text = data[1].split(':')
        for i in range(0,16):
            iv += bytes([int(data[i],16)])
        for hex in hex_text:
            decrypt += bytes([int(hex,16)])

        cipher_aes = AES.new(aeskey, AES.MODE_CBC, iv)
        message = cipher_aes.decrypt(decrypt, -1)
        return message
    else:
        print(str(cipher)+" is not supported")

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

if __name__ == "__main__":
    main()
