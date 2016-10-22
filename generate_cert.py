#!/usr/bin/python3
import subprocess, os

print("Outil de génération de certificat")

def runCommand(cmd_str):
    return subprocess.Popen(cmd_str, shell=True, stdout=subprocess.PIPE).communicate()[0]

certtool = runCommand("command -v certtool")

if len(certtool) > 0:
    print("A - Générer une autorité de certification")
    print("B - Générer un certificat serveur avec CA")
    print("C - Générer un certificat client avec CA")
    print("D - Générer un certificat auto-signé")
    print("Choix :")
    choice = input()

    if choice == "A" or choice == "a":
        print("Entrez le nom commun :")
        name = input()

        while name == "":
            print("Entrez le nom commun :")
            name = input()

        f = open("ca_template.info","w")
        f.write("cn=",name,"\n")
        f.write("ca\n")
        f.write("cert_signing_key\n")
        f.write("expiration_days=700\n")
        f.close()

        print("Entrez le nom de la clé privée [cakey.pem] : ")
        privkey = input()
        if privkey == "":
            privkey="cakey.key"

        generate_key = runCommand("certtool --generate-privkey > {0}".format(privkey))
        print(generate_key)
        print("Entrez le nom du certificat CA :")
        certname = input()
        if certname == "":
            certname="cacert.pem"
        print("Génération du certificat CA")
        self_signed = runCommand("certtool --generate-self-signed --template ca_template.info --load-privkey {0} --outfile {1}".format(privkey,certname))
        print(self_signed)
        runCommand("rm ca_template.info")

        print("Faut-il installer ? (O ou N)")
        install = input()

        if install == "O" or install == "o":
            if os.getuid() == 0:
                print("Où ça ? (/etc/ssl/CA)")
                dest = input()

                if not os.path.isdir(dest):
                    runCommand("mkdir -p {0}".format(dest))

                runCommand("mv {0} {1}".format(certname, dest))
                runCommand("mv {0} {1}".format(privkey, dest))
                runCommand("chmod 440 {0}/{1} {2}/{3}".format(dest, certname, dest, privkey))
                print("Clé privée et certificat installés sous les noms de cacert.pem et cakey.key dans ",dest)
            else:
                print("Droit root non disponible")

    elif choice == "B" or choice == "b":
        print("Génération de certificat serveur")
        print("Entrez le nom de l'organisation :")
        org = input()

        while org == "":
            print("Entrez le nom de l'organisation :")
            org = input()

        print("Entrez le nom commun :")
        cn = input()

        while cn == "":
            print("Entrez le nom commum :")
            cn = input()

        f = open("server_template.info","w")
        f.write("organization = {0}\n".format(org))
        f.write("cn = {0}\n".format(cn))
        f.write("tls_www_server\n")
        f.write("encryption_key\n")
        f.write("signing_key\n")
        f.close()

        print("Entrez le nom de la clé privée [servkey.pem] :")
        privkey = input()

        if privkey == "":
            privkey = "servkey.pem"

        priv_command = runCommand("certtool --generate-privkey > {0}".format(privkey))
        print(priv_command)

        print("Entrez le chemin du certificat CA (/etc/ssl/CA/cacert.pem)")
        cacert = input()

        if cacert == "":
            cacert = "/etc/ssl/CA/cacert.pem"

        print("Entrez le chemin de la clé privée du certificat CA (/etc/ssl/CA/cakey.key)")
        cakey = input()

        if cakey == "":
            cakey = "/etc/ssl/CA/cakey.key"

        print("Entrez le nom du certificat serveur [servcert.pem]")
        servcert = input()

        if servcert == "":
            servcert = "servcert.pem"

        print("Génération du certificat serveur")
        serv_generate = runCommand("certtool --generate-certificate --template server_template.info --load-privkey {0} --load-ca-certificate {1} --load-ca-privkey {2} --outfile {3}".format(privkey, cacert, cakey, servcert))
        print(serv_generate)
        runCommand("rm server_template.info")

        print("Faut-il l'installer ? (O ou N)")
        install = input()

        if install == "o" or install == "O":
            if os.getuid() == 0:
                print("Où ça (certificat) ? (/etc/ssl/certs)")
                destcert = input()
                print("Ou ça (clé privée) ? (/etc/ssl/private)")
                destkey = input()

                if destcert == "":
                    destcert = "/etc/ssl/certs"
                if destkey == "":
                    destkey = "/etc/ssl/private"

                if not os.path.isdir(destcert):
                    runCommand("mkdir -p {0}".format(destcert))
                if not os.path.isdir(destkey):
                    runCommand("mkdir -p {0}".format(destkey))

                runCommand("mv {0} {1}".format(servcert, destcert))
                runCommand("mv {0} {1}".format(privkey, destkey))
                runCommand("chmod 440 {0}/{1} {2}/{3}".format(destcert,servcert,destkey,privkey))
                print("Certificat et clé privée installés dans {0} et {1}".format(destcert, destkey))

    elif choice == "c" or choice == "C":
        print("Génération de certificat client pour un client")
        print("Entrez le code du pays (FR) :")
        country = input()

        if country == "":
            country = "FR"

        print("Entrez un nom de région/état (France) :")
        state = input()

        if state == "":
            state = "France"

        print("Entrez un nom de localité (NONE) :")
        locality = input()

        if locality == "":
            locality = "NONE"

        print("Entrez un nom d'organisation :")
        org = input()

        while org == "":
            print("Entrez un nom d'organisation :")
            org = input()

        print("Entrez un nom commun (client) :")
        cn = input()

        while cn == "":
            print("Entrez un nom commun (client) :")
            cn = input()

        f = open("client_template.info","w")
        f.write("country = {0}\n".format(country))
        f.write("state = {0}\n".format(state))
        f.write("locality = {0}\n".format(locality))
        f.write("organization = {0}\n".format(org))
        f.write("cn = {0}\n".format(cn))
        f.write("tls_www_client\n")
        f.write("encryption_key\n")
        f.write("signing_key\n")
        f.close()

        print("Entrez le chemin de la clé privée [clientkey.key]")
        privkey = input()

        if privkey == "":
            privkey = "clientkey.key"

        priv_command = runCommand("certtool --generate-privkey > {0}".format(privkey))
        print(priv_command)

        print("Entrez le chemin du certificat (/etc/ssl/CA/cacert.pem) :")
        cacert = input()

        if cacert == "":
            cacert = "/etc/ssl/CA/cacert.pem"

        print("Entrez le chemin de la clé privée (/etc/ssl/CA/cakey.key")
        cakey = input()

        if cakey == "":
            cakey = "/etc/ssl/CA/cakey.key"

        print("Entrez le nom du certificat client [clientcert.pem] : ")
        clientcert = input()

        if clientcert == "":
            clientcert = "clientcert.pem"


        print("certtool --generate-certificate --template client_template.info --load-privkey {0} --load-ca-certificate {1} --load-ca-privkey {2} --outfile {3}".format(privkey,cacert,cakey,clientcert))
        client_generate = runCommand("certtool --generate-certificate --template client_template.info --load-privkey {0} --load-ca-certificate {1} --load-ca-privkey {2} --outfile {3}".format(privkey,cacert,cakey,clientcert))
        print(client_generate)
        runCommand("rm client_template.info")

        print("Faut-il l'installer ? (O ou N)")
        install = input()

        if install == "O" or install == "o":
            if os.getuid() == 0:
                print("Où ça (certificat) ? (/etc/ssl/certs)")
                destcert = input()
                print("Où ça (clé privée) ? (/etc/ssl/private)")
                destkey = input()

                if not os.path.isdir(destcert):
                    runCommand("mkdir -p {0}".format(destcert))
                if not os.path.isdir(destkey):
                    runCommand("mkdir -p {0}".format(destkey))

                runCommand("mv {0} {1}".format(clientcert, destcert))
                runCommand("mv {0} {1}".format(privkey, destkey))
                runCommand("chmod 440 {0}/{1} {2}/{3}".format(destcert, clientcert, destkey, privkey))

    elif choice == "D" or choice == "d":
        print("Génération de certificat auto-signé pour un serveur")
        print("Entrez le code du pays (FR) :")
        country = input()

        if country == "":
            country = "FR"

        print("Entrez un nom de région/état (France) :")
        state = input()

        if state == "":
            state = "France"

        print("Entrez un nom de localité (NONE) :")
        locality = input()

        if locality == "":
            locality = "NONE"

        print("Entrez un nom d'organisation :")
        org = input()

        while org == "":
            print("Entrez un nom d'organisation :")
            org = input()

        print("Entrez un nom commun (client) :")
        cn = input()

        while cn == "":
            print("Entrez un nom commun (client) :")
            cn = input()

        print("Ajouter un nom de domaine au certificat (aucun) : ")
        dnsname = input()

        f = open("client_template.info","w")
        if dnsname != "":
            f.write("dns_name = {0}\n".format(dnsname))

        print("Voulez-vous rajouter un nom de domaine (O ou N) :")
        add_dns = input()
        while add_dns == "O" or add_dns == "o":
            f.write("dns_name = {0}\n".format(dnsname))
            print("Voulez-vous rajouter un nom de domaine (O ou N) :")
            add_dns = input()

        f.write("country = {0}\n".format(country))
        f.write("state = {0}\n".format(state))
        f.write("locality = {0}\n".format(locality))
        f.write("organization = {0}\n".format(org))
        f.write("cn = {0}\n".format(cn))
        f.write("tls_www_client\n")
        f.write("encryption_key\n")
        f.write("signing_key\n")
        f.close()

        print("Entrez un nom pour le certiticat (clientcert.pem) :")
        clientcert = input()

        if clientcert == "":
            clientcert = "clientcert.pem"

        print("Entrez un nom de clé privée (clientkey.key) :")
        clientkey = input()

        if clientkey == "":
            clientkey = "clientkey.key"

        generate_cert = runCommand("certtool --generate-self-signed --load-privkey {0} --template client_template.info --outfile {2}".format(clientkey, clientcert))
        print(generate_cert)
        runCommand("rm client_template.info")

        if install == "O" or install == "o":
            if os.getuid() == 0:
                print("Où ça (certificat) ? (/etc/ssl/certs)")
                destcert = input()
                print("Où ça (clé privée) ? (/etc/ssl/private)")
                destkey = input()

                if not os.path.isdir(destcert):
                    runCommand("mkdir -p {0}".format(destcert))
                if not os.path.isdir(destkey):
                    runCommand("mkdir -p {0}".format(destkey))

                runCommand("mv {0} {1}".format(clientcert, destcert))
                runCommand("mv {0} {1}".format(clientkey, destkey))
                runCommand("chmod 440 {0}/{1} {2}/{3}".format(destcert, clientcert, destkey, clientkey))

else:
    print("certtool n'est pas installé. Disponible dans le package de gnutls")
