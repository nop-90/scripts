#!/usr/bin/python3
from bs4 import BeautifulSoup
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA
from Crypto.Cipher import AES
import base64
import urllib.request
import sys
import subprocess
import argparse
import time
import os.path
import getpass

from rsa_convert import *
from rsa_attacks import *

def main():
    args()

class RSAToolbox:
    def isPrime(self, num):
        isPrime = True
        for i in range(1,isPrime):
            if num % i != 0:
                isPrime = False

        return isPrime

    def hexpair_to_int(self, number):
        hexnumber = number.replace(":")
        return int(number,16)

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
        else:
            if args.f == 'dec' or args.f == None:
                print("Exponant : "+str(input_key.getKey()['e']))
                print("Modulus : "+str(input_key.getKey()['n']))
                if isinstance(input_key, PrivateKey):
                    print("Prime 1 : "+str(input_key.getKey()['p']))
                    print("Prime 2 : "+str(input_key.getKey()['q']))
                    print("Phi : "+str((input_key.getKey()['p']-1)*(input_key.getKey()['q']-1)))
                    print("Private exponant : "+str(input_key.getKey()['d']))
            elif args.f == 'hex':
                print("Exponant : "+hex(input_key.getKey()['e']))
                print("Modulus : "+hex(input_key.getKey()['n']))
                if isinstance(input_key, PrivateKey):
                    print("Prime 1 : "+hex(input_key.getKey()['p']))
                    print("Prime 2 : "+hex(input_key.getKey()['q']))
                    print("Phi : "+hex((input_key.getKey()['p']-1)*(input_key.getKey()['q']-1)))
                    print("Private exponant : "+hex(input_key.getKey()['d']))
            elif args.f == 'hexpair':
                print("Exponant : "+self.int_to_hexpair(input_key.getKey()['e']))
                print("Modulus : "+self.int_to_hexpair(input_key.getKey()['n']))
                if isinstance(input_key, PrivateKey):
                    print("Prime 1 : "+self.int_to_hexpair(input_key.getKey()['p']))
                    print("Prime 2 : "+self.int_to_hexpair(input_key.getKey()['q']))
                    print("Phi : "+self.int_to_hexpair((input_key.getKey()['p']-1)*(input_key.getKey()['q']-1)))
                    print("Private exponant : "+self.int_to_hexpair(input_key.getKey()['d']))
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
        if args.ic != None:
            input_key = PublicKey(args.ic).getKey()
            cipher = PKCS1_OAEP.new(RSA.construct((input_key['n'],input_key['e'])))

            if args.i == "-":
                data = sys.stdin.read()
            else:
                try:
                    data = open(args.i, 'r').read()
                except IOError:
                    print("Input file not found")
                    exit()
            try:
                message = cipher.encrypt(data.encode('utf-8'))
            except ValueError as e:
                print("Your key size is too small to encode this text with RSA (try increasing the modulus length)")

            if args.o != None:
                try:
                    output = open(args.o, 'w')
                    output.write(base64.b64encode(message).decode('utf-8'))
                    output.close()
                except IOError:
                    print("Output file could not be created")
                    exit()
            else:
                print(base64.b64encode(message).decode('utf-8'))

            """
                AES
                aeskey = Random.new().read(24)
                iv = Random.new().read(AES.block_size)
                cipher_aes = AES.new(aeskey, AES.MODE_CBC, iv)
                msg = iv + cipher_aes.encrypt(data)

                random_gen = Random.new().read
                ciphertext = cipher.encrypt(aeskey)
                return [':'.join([hex(int(cipherbit)).replace('0x','') for bit in ciphertext]),':'.join([hex(int(text_bit)).replace('0x','') for text_bit in msg])]
            """

    def handle_decipher(self, args):
        if args.ic != None:
            input_key = PrivateKey(args.ic).getKey()
            decipher = PKCS1_OAEP.new(RSA.construct((input_key['n'],input_key['e'],input_key['d'],input_key['p'],input_key['q'])))

            if args.i == '-':
                data = sys.stdin.read()
            else:
                try:
                    data = base64.b64decode(open(args.i, 'r').read())
                except IOError:
                    print("Input file not found")
                    exit()
            try:
                message = decipher.decrypt(data)
                if args.o != None:
                    try:
                        output = open(args.o, 'w')
                        output.write(message)
                        output.close()
                    except IOError:
                        print("Output file could not be created")
                        exit()
                else:
                    print(message)
            except Exception as e:
                print(e)
                exit()

    def handle_crack(self, args):
        input_key = PublicKey(args.i).getKey()
        decrypt = RSAAttack(input_key)
        if args.fac:
            priv_key_found = decrypt.factordb()
            key_str = priv_key_found.getKey()
            if args.o != None:
                if args.of != None:
                    try:
                        output = open(args.o, "w")
                        output.write(priv_key_found.export(args.of))
                        output.close()
                    except IOError:
                        print("Output key file could not be created")
                        exit()
                else:
                    print("Output private key format was not specified")
            else:
                print(key_str)
        elif args.w:
            priv_key_found = decrypt.wiener()
            key_str = priv_key_found.getKey()
            if args.o != None:
                if args.of != None:
                    try:
                        output = open(args.o, "w")
                        output.write(priv_key_found.export(args.of))
                        output.close()
                    except IOError:
                        print("Output key file could not be created")
                        exit()
                else:
                    print("Output private key format was not specified")
            else:
                print(key_str)
        elif args.sp:
            priv_key_found = decrypt.smallp()
            key_str = priv_key_found.getKey()
            if args.o != None:
                if args.of != None:
                    try:
                        output = open(args.o, "w")
                        output.write(priv_key_found.export(args.of))
                        output.close()
                    except IOError:
                        print("Output key file could not be created")
                        exit()
                else:
                    print("Output private key format was not specified")
            else:
                print(key_str)
        elif args.fer:
            priv_key_found = decrypt.fermat()
            key_str = priv_key_found.getKey()
            if args.o != None:
                if args.of != None:
                    try:
                        output = open(args.o, "w")
                        output.write(priv_key_found.export(args.of))
                        output.close()
                    except IOError:
                        print("Output key file could not be created")
                        exit()
                else:
                    print("Output private key format was not specified")
            else:
                print(key_str)
        elif args.qs:
            priv_key_found = decrypt.siqs()
            key_str = priv_key_found.getKey()
            if args.o != None:
                if args.of != None:
                    try:
                        output = open(args.o, "w")
                        output.write(priv_key_found.export(args.of))
                        output.close()
                    except IOError:
                        print("Output key file could not be created")
                        exit()
                else:
                    print("Output private key format was not specified")
            else:
                print(key_str)
        elif args.a:
            # TODO
            pass
        return

    def handle_generate(self, args):
        generate = None
        if args.p != None and args.q != None and args.d != None:
            if args.fi != None:
                if args.fi == "dec":
                    try:
                        e = int(args.e)
                        n = int(args.m)
                        d = int(args.d)
                        # TODO verify if private exponant modular inverse is correct
                        p = int(args.p)
                        q = int(args.q)
                        if not self.isPrime(p) or not self.isPrime(q):
                            raise RSAException("Wrong generators, p or/and q are not prime")
                        generate = PrivateKey({"e":e, "n":n, "d":d, "p":p, "q":q})
                    except ValueError:
                        print("One or more of the input numbers are not in decimal format")
                        exit()
                elif args.fi == "hexpair":
                    try:
                        e = hexpair_to_int(args.e)
                        n = hexpair_to_int(args.m)
                        d = hexpair_to_int(args.d)
                        p = hexpair_to_int(args.p)
                        q = hexpair_to_int(args.q)
                        if not self.isPrime(p) or not self.isPrime(q):
                            raise RSAException("Wrong generators, p or/and q are not prime")
                        generate = PrivateKey({"e":e, "n":n, "d":d, "p":p, "q":q})
                    except ValueError:
                        print("One or more of the input numbers are not in hexadecimal format")
                        exit()
                elif args.fi == "hex":
                    try:
                        e = int(args.e, 16)
                        n = int(args.m, 16)
                        d = int(args.d, 16)
                        p = int(args.p, 16)
                        q = int(args.q, 16)
                        if not self.isPrime(p) or not self.isPrime(q):
                            raise RSAException("Wrong generators, p or/and q are not prime")
                        generate = PrivateKey({"e":e, "n":n, "d":d, "p":p, "q":q})
                    except ValueError:
                        print("One or more of the input numbers are not in hexadecimal format")
                        exit()
            else:
                try:
                    e = int(args.e)
                    n = int(args.m)
                    d = int(args.d)
                    p = int(args.p)
                    q = int(args.q)
                    if not self.isPrime(p) or not self.isPrime(q):
                        raise RSAException("Wrong generators, p or/and q are not prime")
                    generate = PrivateKey({"e":e, "n":n, "d":d, "p":p, "q":q})
                except ValueError:
                    print("One or more of the input numbers are not in decimal format")
                    exit()
        else:
            if args.fi != None:
                if args.fi == "dec":
                    try:
                        e = int(args.e)
                        n = int(args.m)
                        generate = PublicKey({"e":e, "n":n})
                    except ValueError:
                        print("Exponant or modulus are not in decimal format")
                        exit()
                elif args.fi == "hexpair":
                    try:
                        e = hexpair_to_int(args.e)
                        n = hexpair_to_int(args.m)
                        generate = PublicKey({"e":e, "n":n})
                    except ValueError:
                        print("Exponant or modulus are not in hexadecimal format")
                        exit()
                elif args.fi == "hex":
                    try:
                        e = int(args.e, 16)
                        n = int(args.m, 16)
                        generate = PublicKey({"e":e, "n":n})
                    except ValueError:
                        print("Exponant or modulus are not in hexadecimal format")
                        exit()
            else:
                try:
                    e = int(args.e)
                    n = int(args.m)
                    generate = PublicKey({"e":e, "n":n})
                except ValueError:
                    print("Exponant or modulus are not in decimal format")
                    exit()

        if args.f == "pkcs8" or args.f == "ssh" or args.f == "pkcs1":
            if args.o != None:
                f_write = open(args.o, 'w+')
                if (args.f == "pkcs1" or args.f == "pkcs8") and isinstance(generate, PublicKey):
                    f_write.write(generate.export("pkcs"))
                else:
                    f_write.write(generate.export(args.f))
                f_write.close()
            else:
                if (args.f == "pkcs1" or args.f == "pkcs8") and isinstance(generate, PublicKey):
                    print(generate.export("pkcs"))
                else:
                    print(generate.export(args.f))

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
    parser_list.add_argument('-i', action="store", help="input file")
    parser_list = subparser.add_parser('decipher')
    parser_list.add_argument('-o', action="store", help="output file")
    parser_list.add_argument('-ic', action="store", required=True, help="input private key file", type=lambda x: is_valid_file(parser, x))
    parser_list.add_argument('-i', action="store", required=True, help="input file")
    parser_list = subparser.add_parser('crack')
    parser_list.add_argument('-i', action="store", help="input key file", required=True, type=lambda x: is_valid_file(parser,x))
    parser_list.add_argument('-fac', action="store_true", help="inspect for known factor")
    parser_list.add_argument('-w', action="store_true", help="inspect for wiener vulnerability")
    parser_list.add_argument('-sp', action="store_true", help="inspect for small prime factorization")
    parser_list.add_argument('-fer', action="store_true", help="inspect for fermat factorization")
    parser_list.add_argument('-qs', action="store_true", help="try factorizing with Self-Initializing Quadratic Sieve")
    parser_list.add_argument('-a', action="store_true", help="try all attacks")
    parser_list.add_argument('-o', action="store", help="output private key file")
    parser_list.add_argument('-of', action="store", help="output private key file format", choices=['pkcs8', 'pkcs1', 'ssh'])
    parser_list = subparser.add_parser('generate')
    parser_list.add_argument('-fi', action="store", choices=['dec', 'hex', 'hexpair'], help="input data format")
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

if __name__ == "__main__":
    main()
