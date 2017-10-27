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

class RSAToolbox:
    def is_prime(self, num):
        isPrime = True
        for i in range(1,isPrime):
            if num % i != 0:
                isPrime = False

        return isPrime

    def int_to_hexpair(self, number):
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

    def handle_error(self):
        print("That should not append")

    def handle_print(self, args):
        input_key = ""
        if 'i' in args:
            try:
                input_key = PrivateKey(args.i)
            except PrivException as e:
                try:
                    input_key = PublicKey(args.i)
                except PubException as e:
                    print("Not a private key, neither a public key")
                    exit()
            except IOError as e:
                print(e)
                exit()
        else:
            print("No input key provided")
            exit()

        if args.e:
            if args.f == 'dec' or args.f == None:
                print(str(input_key.getKey()['e']))
            elif args.f == 'hex':
                print(hex(input_key.getKey()['e']))
            elif args.f == 'hexpair':
                print(self.int_to_hexpair(input_key.getKey()['e']))
            else:
                print('Wrong output format for printing, use -f with "dec","hex" or "hexpair")')
            exit()
        elif args.p:
            if isinstance(input_key, PrivateKey):
                if args.f == 'dec' or args.f == None:
                    print(str(input_key.getKey()['p']))
                elif args.f == 'hex':
                    print(hex(input_key.getKey()['p']))
                elif args.f == 'hexpair':
                    print(self.int_to_hexpair(input_key.getKey()['p']))
                else:
                    print('Wrong output format for printing, use -f with "dec","hex" or "hexpair")')
                    exit()
            else:
                print('Not a private key')
            exit()
        elif args.q:
            if isinstance(input_key, PrivateKey):
                if args.f == 'dec' or args.f == None:
                    print(str(input_key.getKey()['q']))
                elif args.f == 'hex':
                    print(hex(input_key.getKey()['q']))
                elif args.f == 'hexpair':
                    print(self.int_to_hexpair(input_key.getKey()['q']))
                else:
                    print('Wrong output format for printing, use -f with "dec","hex" or "hexpair")')
                    exit()
            else:
                print('Not a private key')
            exit()
        elif args.d:
            if isinstance(input_key, PrivateKey):
                if args.f == 'dec' or args.f == None:
                    print(str(input_key.getKey()['d']))
                elif args.f == 'hex':
                    print(hex(input_key.getKey()['d']))
                elif args.f == 'hexpair':
                    print(self.int_to_hexpair(input_key.getKey()['d']))
                else:
                    print('Wrong output format for printing, use -f with "dec","hex" or "hexpair")')
                    exit()
            else:
                print('Not a private key')
            exit()
        elif args.m:
            if args.f == 'dec' or args.f == None:
                print(str(input_key.getKey()['n']))
            elif args.f == 'hex':
                print(hex(input_key.getKey()['n']))
            elif args.f == 'hexpair':
                print(self.int_to_hexpair(input_key.getKey()['n']))
            else:
                print('Wrong output format for printing, use -f with "dec", "hex" or "hexpair")')
            exit()
        elif args.phi:
            if isinstance(input_key, PrivateKey):
                if args.f == 'dec' or args.f == None:
                    print(str((input_key.getKey()['p']-1)*(input_key.getKey()['q']-1)))
                elif args.f == 'hex':
                    print(hex((input_key.getKey()['p']-1)*(input_key.getKey()['q']-1)))
                elif args.f == 'hexpair':
                    print(self.int_to_hexpair((input_key.getKey()['p']-1)*(input_key.getKey()['q']-1)))
                else:
                    print('Wrong output format for printing, use -f with "dec", "hex" or "hexpair")')
                    exit()
                print('phi : '+(input_key.getKey()['p']-1)*(input_key.getKey()['q']-1))
            else:
                print('Not a private key')
            exit()
        elif args.b:
            # TODO
            pass
        elif args.a:
            if args.f == 'dec' or args.f == None:
                print(str(input_key.getKey()['e']))
                print(str(input_key.getKey()['n']))
                if isinstance(input_key, PrivateKey):
                    print(str(input_key.getKey()['p']))
                    print(str(input_key.getKey()['q']))
                    print(str((input_key.getKey()['p']-1)*(input_key.getKey()['q']-1)))
                    print(str(input_key.getKey()['d']))
            elif args.f == 'hex':
                print(hex(input_key.getKey()['e']))
                print(hex(input_key.getKey()['n']))
                if isinstance(input_key, PrivateKey):
                    print(hex(input_key.getKey()['p']))
                    print(hex(input_key.getKey()['q']))
                    print(hex((input_key.getKey()['p']-1)*(input_key.getKey()['q']-1)))
                    print(hex(input_key.getKey()['d']))
            elif args.f == 'hexpair':
                print(self.int_to_hexpair(input_key.getKey()['e']))
                print(self.int_to_hexpair(input_key.getKey()['n']))
                if isinstance(input_key, PrivateKey):
                    print(self.int_to_hexpair(input_key.getKey()['p']))
                    print(self.int_to_hexpair(input_key.getKey()['q']))
                    print(self.int_to_hexpair((input_key.getKey()['p']-1)*(input_key.getKey()['q']-1)))
                    print(self.int_to_hexpair(input_key.getKey()['d']))
            else:
                print('Wrong output format for printing, use -f with "dec", "hex" or "hexpair")')
            exit()

    def handle_convert(self, args):
        if args.i != None:
            input_key = ""
            output_key = ""
            try:
                input_key = PrivateKey(args.i)
            except PrivException as e:
                try:
                    input_key = PublicKey(args.i)
                except PubException as e:
                    print("Not a private key, neither a public key")
                    exit()
            except IOError as e:
                print(e)
                exit()
            try:
                output_key = input_key.convert(args.f)
            except RSAException as e:
                print(e)
                exit()

            if args.o != None:
                write_out = open(args.o,'w+')
                write_out.write(output_key)
                write_out.close()
            else:
                print(output_key)
        else:
            input_key = ""
            output_key = ""
            stdin_key = sys.stdin.read()
            try:
                input_key = PrivateKey(stdin_key)
            except PrivException as e:
                try:
                    input_key = PublicKey(stdin_key)
                except PubException as e:
                    print("Not a private key, neither a public key")
                    exit()
            except IOError as e:
                print(e)
                exit()

            try:
                output_key = input_key.convert(args.f)
            except RSAException as e:
                print(e)
                exit()

            if args.o != None:
                write_out = open(args.o,'w+')
                write_out.write(output_key)
                write_out.close()
            else:
                print(output_key)

    def handle_cipher(self, args):
        return
    def handle_decipher(self, args):
        return
    def handle_crack(self, args):
        return
    def handle_generate(self, args):
        return

def is_valid_file(parser, arg):
    if not os.path.exists(arg):
        parser.error("The file %s does not exist!" % arg)
    return arg

def args():
    parser = argparse.ArgumentParser()
    subparser = parser.add_subparsers()
    parser_list = subparser.add_parser('print')
    parser_list.add_argument('-i', action="store", required=True, help="input key file", type=lambda x: is_valid_file(parser, x))
    parser_list.add_argument('-m', action="store_true", help="print modulus from key")
    parser_list.add_argument('-phi', action="store_true", help="print Phi number from key")
    parser_list.add_argument('-e', action="store_true", help="print exponant from key")
    parser_list.add_argument('-d', action="store_true", help="print private exponant from key")
    parser_list.add_argument('-p', action="store_true", help="print first prime number")
    parser_list.add_argument('-q', action="store_true", help="print second prime number")
    parser_list.add_argument('-f', action="store", choices=['dec', 'hex', 'hexpair'], help="print format")
    parser_list.add_argument('-b', action="store_true", help="show byte length of input key")
    parser_list.add_argument('-a', action="store_true", help="print all information")
    parser_list = subparser.add_parser('convert')
    parser_list.add_argument('-o', action="store", help="output file")
    parser_list.add_argument('-f', action="store", required=True, choices=['pkcs8', 'pkcs1', 'ssh'], help="output format")
    parser_list.add_argument('-i', action="store", help="input file", type=lambda x: is_valid_file(parser, x))
    parser_list = subparser.add_parser('cipher')
    parser_list.add_argument('-o', action="store", help="output file")
    parser_list.add_argument('-ic', action="store", required=True, help="input key file", type=lambda x: is_valid_file(parser, x))
    parser_list.add_argument('-i', action="store", help="input file", type=lambda x: is_valid_file(parser, x))
    parser_list = subparser.add_parser('decipher')
    parser_list.add_argument('-o', action="store", help="output file")
    parser_list.add_argument('-ic', action="store", required=True, help="input private key file", type=lambda x: is_valid_file(parser, x))
    parser_list.add_argument('-i', action="store", help="input file", type=lambda x: is_valid_file(parser, x))
    parser_list = subparser.add_parser('crack')
    parser_list.add_argument('-fac', action="store_true", help="output file or stdout")
    parser_list.add_argument('-w', action="store_true", help="input private key file")
    parser_list.add_argument('-sp', action="store_true", help="input stdin or file")
    parser_list.add_argument('-fer', action="store_true", help="output file or stdout")
    parser_list.add_argument('-com', action="store_true", help="input private key file")
    parser_list.add_argument('-qs', action="store_true", help="input stdin or file")
    parser_list.add_argument('-a', action="store_true", help="input stdin or file")
    parser_list = subparser.add_parser('generate')
    parser_list.add_argument('-o', action="store", help="output key file destination")
    parser_list.add_argument('-m', action="store", required=True, help="input modulus for export")
    parser_list.add_argument('-e', action="store", required=True, help="input exponant from key")
    parser_list.add_argument('-p', action="store", help="input first prime number")
    parser_list.add_argument('-q', action="store", help="input second prime number")
    parser_list.add_argument('-d', action="store", help="input private exponant prime number")
    parser_list.add_argument('-f', action="store", required=True, choices=['pkcs8', 'pkcs1', 'ssh'], help="output key type")
    args = parser.parse_args()

    RSA = RSAToolbox()
    getattr(RSA, 'handle_'+sys.argv[1], "handle_error")(args)

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
