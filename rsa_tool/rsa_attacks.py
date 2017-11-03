#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
RsaCtfTool-Continued - RSA CTF Cracking tool for simple CTF challenges
author: sourcekris (@CTFKris)

Original author's license below:
----------------------------------------------------------------------------
"THE BEER-WARE LICENSE" (Revision 42):
ganapati (@G4N4P4T1) wrote this file. As long as you retain this notice you
can do whatever you want with this stuff. If we meet some day, and you think
this stuff is worth it, you can buy me a beer in return.
----------------------------------------------------------------------------
"""

from Crypto.PublicKey import RSA
import signal
import gmpy
import requests
import re
import argparse
import os
import subprocess
from glob import glob
from bs4 import BeautifulSoup
import sys
from sympy.solvers import solve
from sympy import Symbol, primerange

from rsa_convert import *

class FactorizationError(Exception):
    pass

def isqrt(n):
  x = n
  y = (x + n // x) // 2
  while y < x:
    x = y
    y = (x + n // x) // 2
  return x

def fermat(n):
    a = isqrt(n)
    b2 = a*a - n
    b = isqrt(n)
    count = 0
    while b*b != b2:
        a = a + 1
        b2 = a*a - n
        b = isqrt(b2)
        count += 1
    p=a+b
    q=a-b
    assert n == p * q
    return p, q

# A reimplementation of pablocelayes rsa-wiener-attack for this purpose
# https://github.com/pablocelayes/rsa-wiener-attack/
class WienerAttack(object):
    def rational_to_contfrac (self, x, y):
        a = x//y
        if a * y == x:
            return [a]
        else:
            pquotients = self.rational_to_contfrac(y, x - a * y)
            pquotients.insert(0, a)
            return pquotients

    def convergents_from_contfrac(self, frac):
        convs = [];
        for i in range(len(frac)):
            convs.append(self.contfrac_to_rational(frac[0:i]))
        return convs

    def contfrac_to_rational (self, frac):
        if len(frac) == 0:
            return (0,1)
        elif len(frac) == 1:
            return (frac[0], 1)
        else:
            remainder = frac[1:len(frac)]
            (num, denom) = self.contfrac_to_rational(remainder)
            return (frac[0] * num + denom, num)

    def is_perfect_square(self, n):
        h = n & 0xF;
        if h > 9:
            return -1

        if ( h != 2 and h != 3 and h != 5 and h != 6 and h != 7 and h != 8 ):
            t = self.isqrt(n)
            if t*t == n:
                return t
            else:
                return -1

        return -1

    def isqrt(self, n):
        if n == 0:
            return 0
        a, b = divmod(n.bit_length(), 2)
        x = 2**(a+b)
        while True:
            y = (x + n//x)//2
            if y >= x:
                return x
            x = y


    def __init__(self, n, e):
        self.d = None
        self.p = None
        self.q = None
        sys.setrecursionlimit(100000)
        frac = self.rational_to_contfrac(e, n)
        convergents = self.convergents_from_contfrac(frac)

        for (k,d) in convergents:
            if k!=0 and (e*d-1)%k == 0:
                phi = (e*d-1)//k
                s = n - phi + 1
                discr = s*s - 4*n
                if(discr>=0):
                    t = self.is_perfect_square(discr)
                    if t!=-1 and (s+t)%2==0:
                        self.d = d
                        x = Symbol('x')
                        roots = solve(x**2 - s*x + n, x)
                        if len(roots) == 2:
                            self.p = roots[0]
                            self.q = roots[1]
                        break

class SiqsAttack(object):
    def __init__(self, n):
        # Configuration
        self.yafubin = "./yafu" # where the binary is
        self.threads = 2       # number of threads
        self.maxtime = 180     # max time to try the sieve

        self.n = n
        self.p = None
        self.q = None
        self.verbose = False

    def testyafu(self):
        with open('/dev/null') as DN:
            try:
                yafutest = subprocess.check_output([self.yafubin,'siqs(1549388302999519)'], stderr=DN)
            except:
                yafutest = ""

        if '48670331' in yafutest:
            return True
        else:
            return False


    def checkyafu(self):
        # check if yafu exists and we can execute it
        if os.path.isfile(self.yafubin) and os.access(self.yafubin, os.X_OK):
            return True
        else:
            return False

    def benchmarksiqs(self):
        # NYI
        # return the time to factor a 256 bit RSA modulus
        return

    def doattack(self):
        with open('/dev/null') as DN:
            yafurun = subprocess.check_output(
                [self.yafubin,'siqs('+str(self.n)+')',
                 '-siqsT',  str(self.maxtime),
                 '-threads',str(self.threads)], stderr=DN)

            primesfound = []

            if 'input too big for SIQS' in yafurun:
                raise FactorizationError('input too big for SIQS')

            for line in yafurun.splitlines():
                if re.search('^P[0-9]+\ =\ [0-9]+$',line):
                    primesfound.append(int(line.split('=')[1]))

            if len(primesfound) == 2:
                self.p = primesfound[0]
                self.q = primesfound[1]

            if len(primesfound) > 2:
                raise FactorizationError("> 2 primes found. Is key multiprime?")

            if len(primesfound) < 2:
                raise("SIQS did not factor modulus")

        return

class RSAAttack:
    pub_key = {}

    def __init__(self, pubkey):
        self.pub_key = pubkey

    def hastads(self):
        # Hastad attack for low public exponent, this has found success for e = 3, and e = 5 previously
        if self.pub_key.e <= 11 and self.args.uncipher is not None:
            orig = s2n(self.cipher)
            c = orig
            while True:
                m = gmpy.root(c, self.pub_key.e)[0]
                if pow(m, self.pub_key.e, self.pub_key.n) == orig:
                    self.unciphered = n2s(m)
                    break
                c += self.pub_key.n
        return

    def factordb(self):
        # if factordb returns some math to derive the prime, solve for p without using an eval
        def solveforp(equation):
            try:
                if '^' in equation: k,j = equation.split('^')
                if '-' in j: j,sub = j.split('-')
                eq = map(int, [k,j,sub])
                return pow(eq[0],eq[1])-eq[2]
            except Exception as e:
                raise FactorizationError("Unable to compute equation from factordb")

        # Factors available online?
        try:
            url_1 = 'http://www.factordb.com/index.php?query=%i'
            url_2 = 'http://www.factordb.com/index.php?id=%s'
            s = requests.Session()
            r = s.get(url_1 % self.pub_key['n'])
            regex = re.compile("index\.php\?id\=([0-9]+)", re.IGNORECASE)
            ids = regex.findall(r.text)
            p_id = ids[1]
            q_id = ids[2]
            # bugfix: See https://github.com/sourcekris/RsaCtfTool/commit/16d4bb258ebb4579aba2bfc185b3f717d2d91330#commitcomment-21878835
            regex = re.compile("value=\"([0-9\^\-]+)\"", re.IGNORECASE)
            r_1 = s.get(url_2 % p_id)
            r_2 = s.get(url_2 % q_id)
            key_p = regex.findall(r_1.text)[0]
            key_q = regex.findall(r_2.text)[0]
            p = int(key_p) if key_p.isdigit() else solveforp(key_p)
            q = int(key_q) if key_q.isdigit() else solveforp(key_q)
            if p == q == self.pub_key['n']:
                raise FactorizationError()
            self.priv_key = PrivateKey({"p":p, "q":q, "e":self.pub_key['e'], "n":self.pub_key['n']})
            return self.priv_key
        except Exception as e:
            raise FactorizationError("Unable to find factors online")

    def wiener(self):
        # Wiener's attack
        wiener = WienerAttack(self.pub_key['n'], self.pub_key['e'])
        if wiener.p is not None and wiener.q is not None:
            self.priv_key = PrivateKey({'p': int(wiener.p), 'q':int(wiener.q), 'e': self.pub_key['e'], 'n': self.pub_key['n']})
        else:
            raise FactorizationError("Unable to use Weiner attack on this key")
        return self.priv_key

    def smallp(self):
        # Try an attack where q < 100,000, from BKPCTF2016 - sourcekris
        for prime in list(primerange(0, 100000)):
            if self.pub_key['n'] % prime == 0:
                q = prime
                p = self.pub_key['n'] / q
                self.priv_key = PrivateKey({'p':int(p), 'q':int(q), 'e':self.pub_key['e'], 'n':self.pub_key['n']})
        return self.priv_key

    def fermat(self, fermat_timeout=60):
        # Try an attack where the primes are too close together from BKPCTF2016 - sourcekris
        # this attack module can be optional
        with timeout(seconds=fermat_timeout):
            p,q = fermat(self.pub_key['n'])

        if q is not None:
           self.priv_key = PrivateKey({'p':p, 'q':q, 'e':self.pub_key['e'], 'n':self.pub_key['n']})

        return self.priv_key

    def siqs(self):
        # attempt a Self-Initializing Quadratic Sieve
        if self.pub_key['n'].bit_length() > 1024:
            raise FactorizationError("Modulus too large for SIQS attack module")

        siqsobj = SiqsAttack(self.pub_key['n'])

        if siqsobj.checkyafu() and siqsobj.testyafu():
            siqsobj.doattack()

        if siqsobj.p and siqsobj.q:
            return PrivateKey({'p': siqsobj.p, 'q':siqsobj.q, "e": self.pub_key['e'], "n": self.pub_key['n']})
        else:
            raise FactorizationError("Modulus not found")

"""
    def commonfactors(self):
        # Try to find the gcd between each pair of modulii and resolve the private keys if gcd > 1
        for x in self.attackobjs:
            for y in self.attackobjs:
                if x.pub_key.n != y.pub_key.n:
                    g = gcd(x.pub_key.n, y.pub_key.n)
                    if g != 1:
                        if self.args.verbose and not x.displayed and not y.displayed:
                            print("[*] Found common factor in modulus for " + x.pubkeyfile + " and " + y.pubkeyfile)

                        # update each attackobj with a private_key
                        x.pub_key.p = g
                        x.pub_key.q = x.pub_key.n / g
                        y.pub_key.p = g
                        y.pub_key.q = y.pub_key.n / g
                        x.priv_key = PrivateKey(long(x.pub_key.p),long(x.pub_key.q),
                                                long(x.pub_key.e), long(x.pub_key.n))
                        y.priv_key = PrivateKey(long(y.pub_key.p), long(y.pub_key.q),
                                                long(y.pub_key.e), long(y.pub_key.n))

                    # call attack method to print the private keys at the nullattack step or attack singularly
                    # depending on the success of the gcd operation
                    x.attack()
                    y.attack()

        return
    def ecm(self):
        # use elliptic curve method, may return a prime or may never return
        # only works if the sageworks() function returned True
        if self.args.ecmdigits:
            sageresult = int(subprocess.check_output(['sage', 'ecm.sage', str(self.pub_key.n),str(self.args.ecmdigits)]))
        else:
            sageresult = int(subprocess.check_output(['sage','ecm.sage',str(self.pub_key.n)]))

        if sageresult > 0:
            self.pub_key.p = sageresult
            self.pub_key.q = self.pub_key.n / self.pub_key.p
            self.priv_key = PrivateKey(long(self.pub_key.p), long(self.pub_key.q),
                                       long(self.pub_key.e), long(self.pub_key.n))
        return

    def boneh_durfee(self):
        # use boneh durfee method, should return a d value, else returns 0
        # only works if the sageworks() function returned True
        # many of these problems will be solved by the wiener attack module but perhaps some will fall through to here
        # TODO: get an example public key solvable by boneh_durfee but not wiener
        sageresult = int(subprocess.check_output(['sage','boneh_durfee.sage',str(self.pub_key.n),str(self.pub_key.e)]))

        if sageresult > 0:
            # use PyCrypto _slowmath rsa_construct to resolve p and q from d
            from Crypto.PublicKey import _slowmath
            tmp_priv = _slowmath.rsa_construct(long(self.pub_key.n), long(self.pub_key.e), d=long(sageresult))

            self.pub_key.p = tmp_priv.p
            self.pub_key.q = tmp_priv.q
            self.priv_key = PrivateKey(long(self.pub_key.p), long(self.pub_key.q),
                                       long(self.pub_key.e), long(self.pub_key.n))

        return

    def smallfraction(self):
        # Code/idea from Renaud Lifchitz's talk 15 ways to break RSA security @ OPCDE17
        # only works if the sageworks() function returned True
        sageresult = int(subprocess.check_output(['sage', 'smallfraction.sage',str(self.pub_key.n)]))
        if sageresult > 0:
            self.pub_key.p = sageresult
            self.pub_key.q = self.pub_key.n / self.pub_key.p
            self.priv_key = PrivateKey(long(self.pub_key.p), long(self.pub_key.q),
                                       long(self.pub_key.e), long(self.pub_key.n))
        return

    def noveltyprimes(self):
        # "primes" of the form 31337 - 313333337 - see ekoparty 2015 "rsa 2070"
        # not all numbers in this form are prime but some are (25 digit is prime)
        maxlen = 25 # max number of digits in the final integer
        for i in range(maxlen-4):
            prime = long("3133" + ("3" * i) + "7")
            if self.pub_key.n % prime == 0:
                self.pub_key.q = prime
                self.pub_key.p = self.pub_key.n / self.pub_key.q
                self.priv_key = PrivateKey(long(self.pub_key.p), long(self.pub_key.q),
                                           long(self.pub_key.e), long(self.pub_key.n))
        return

    def comfact_cn(self):
        # Try an attack where the public key has a common factor with the ciphertext - sourcekris
        if self.args.uncipher:
            commonfactor = gcd(self.pub_key.n, s2n(self.cipher))

            if commonfactor > 1:
                self.pub_key.q = commonfactor
                self.pub_key.p = self.pub_key.n / self.pub_key.q
                self.priv_key = PrivateKey(long(self.pub_key.p), long(self.pub_key.q),
                                           long(self.pub_key.e), long(self.pub_key.n))

                unciphered = self.priv_key.decrypt(self.cipher)

        return

    def pastctfprimes(self):
        path = os.path.dirname(os.path.abspath(__file__))
        pastctfprimes_path = os.path.join(path, 'pastctfprimes.txt')
        primes = [long(x) for x in open(pastctfprimes_path,'r').readlines() if not x.startswith('#') and not x.startswith('\n')]
        if self.args.verbose:
            print "[*] Loaded " + str(len(primes)) + " primes"
        for prime in primes:
            if self.pub_key.n % prime == 0:
                self.pub_key.q = prime
                self.pub_key.p = self.pub_key.n / self.pub_key.q
                self.priv_key = PrivateKey(long(self.pub_key.p), long(self.pub_key.q),
                                           long(self.pub_key.e), long(self.pub_key.n))
        return

    def commonmodulus(self):
        # NYI requires support for multiple public keys
        return

    def prime_modulus(self):
        # an attack where the modulus is not a composite number, so the math is unique
        # NYI
        return

    def siqs(self):
        # attempt a Self-Initializing Quadratic Sieve
        # this attack module can be optional
        try:
            from siqs import SiqsAttack
        except ImportError:
            if self.args.verbose:
                print "[*] Warning: Yafu SIQS attack module missing (siqs.py)"
            return

        if self.pub_key.n.bit_length() > 1024:
            print "[*] Warning: Modulus too large for SIQS attack module"
            return


        siqsobj = SiqsAttack(self.args, self.pub_key.n)

        if siqsobj.checkyafu() and siqsobj.testyafu():
            siqsobj.doattack()

        if siqsobj.p and siqsobj.q:
            self.pub_key.q = siqsobj.q
            self.pub_key.p = siqsobj.p
            self.priv_key = PrivateKey(long(self.pub_key.p), long(self.pub_key.q),
                                       long(self.pub_key.e), long(self.pub_key.n))

        return

    def nullattack(self):
        # do nothing, used for multi-key attacks that succeeded so we just print the
        # private key without spending any time factoring
        return

    def attack(self):
        if self.attackobjs is not None:
            self.commonfactors()
        else:
            # loop through implemented attack methods and conduct attacks
            for attack in self.implemented_attacks:
                if self.args.verbose and "nullattack" not in attack.__name__:
                    print "[*] Performing " + attack.__name__ + " attack."

                getattr(self, attack.__name__)()

                # check and print resulting private key
                if self.priv_key is not None:
                    if self.args.private and not self.displayed:
                        print self.priv_key
                        self.displayed = True
                    break

                if self.unciphered is not None:
                    break

            # If we wanted to decrypt, do it now
            if self.args.uncipher is not None and self.priv_key is not None:
                    self.unciphered = self.priv_key.decrypt(self.cipher)
                    print "[+] Clear text : %s" % self.unciphered
            elif self.unciphered is not None:
                    print "[+] Clear text : %s" % self.unciphered
            else:
                if self.args.uncipher is not None:
                    print "[-] Sorry, cracking failed"
"""

# source http://stackoverflow.com/a/22348885
class timeout:
    def __init__(self, seconds=10, error_message='[-] Timeout'):
        self.seconds = seconds
        self.error_message = error_message

    def handle_timeout(self, signum, frame):
        raise FactorizationError(self.error_message)

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)

    def __exit__(self, type, value, traceback):
        signal.alarm(0)

def sageworks():
    # Check if sage is installed and working
    try:
        sageversion = subprocess.check_output(['sage', '-v'])
    except OSError:
        return False

    if 'SageMath version' in sageversion:

        return True
    else:
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='RSA CTF Tool Continued')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--publickey', help='public key file. You can use wildcards for multiple keys.')
    group.add_argument('--createpub', help='Take n and e from cli and just print a public key then exit', action='store_true')
    group.add_argument('--dumpkey', help='Just dump the RSA variables from a key - n,e,d,p,q', action='store_true')
    parser.add_argument('--uncipher', help='uncipher a file', default=None)
    parser.add_argument('--verbose', help='verbose mode (display n, e, p and q)', action='store_true')
    parser.add_argument('--private', help='Display private key if recovered', action='store_true')
    parser.add_argument('--ecmdigits', type=int, help='Optionally an estimate as to how long one of the primes is for ECM method', default=None)
    parser.add_argument('--n', type=long, help='Specify the modulus in --createpub mode.')
    parser.add_argument('--e', type=long, help='Specify the public exponent in --createpub mode.')
    parser.add_argument('--key', help='Specify the input key file in --dumpkey mode.')

    args = parser.parse_args()
