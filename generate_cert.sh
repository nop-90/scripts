#!/usr/bin/zsh

echo "Outil de génération de certificat"
if [ ! -z $(command -v certtool) ]
then
    echo "A - Générer une autorité de certification"
    echo "B - Générer un certificat pour serveur"
    echo "C - Générer un certificat pour client"
    echo "D - Générer un certificat auto-signé"
    echo "Choix : "
    read choice
    if [[ "$choice" = 'A' ]] || [[ "$choice" = 'a' ]]; then
        echo "Entrez le nom de domaine : "
        read domain
        while [[ -z $domain ]]
        do
            echo "Entrez le nom de domaine : "
            read domain
        done
        echo "cn = $domain\n" > ca_template.info
        echo "ca\n" >> ca_template.info
        echo "cert_signing_key\n" >> ca_template.info
        echo "expiration_days = 700" >> ca_template.info
        echo "Entrez le nom de la clé privée (sans extension)[cakey.pem] : "
        read privkey
        if [[ -z $privkey ]]
        then
            privkey="cakey"
        fi
        certtool --generate-privkey > "${privkey}.pem"
        echo "Entrez le nom du certificat CA : "
        read certname
        if [[ -z $certname ]]
        then
            certname="cacert"
        fi
        echo "Génération du certificat CA"
        certtool --generate-self-signed \
                 --template ca_template.info \
                 --load-privkey "${privkey}.pem" \
                 --outfile "${certname}.pem"
        rm ca_template.info
        echo "Faut-il l'installer ? (O ou N)"
        read install
        if [[ ("$install" = "O") ]] || [[ ("$install" = "o") ]]
        then
            echo "Où ça ? (/etc/pki/CA) "
            read dest
            if [ -z $dest ]
            then
                dest="/etc/pki/CA"
            fi
                
            if [ ! -d $dest ]
            then
                sudo mkdir -p $dest
            fi
            sudo mv ${certname}.pem $dest/cacert.pem
            sudo mv ${privkey}.pem $dest/cakey.pem
            sudo chmod 440 $dest/cacert.pem $dest/cakey.pem
            echo "Clé privée et certificat installés sous les noms de cacert.pem et cakey.pem dans $dest"
        fi
    elif [[ "$choice" = 'B' ]] || [[ "$choice" = 'b' ]]
    then
        echo "Génération de certificat serveur"
        echo "Entrez le nom de votre organisation : "
        read org
        while [ -z $org ]
        do 
            echo "Entrez le nom de votre organisation : "
            read org
        done
        echo "Entrez le nom de domaine : "
        read domain
        while [ -z $domain ]
        do
            echo "Entrez le nom de domaine : "
            read domain
        done
        echo "organization = $org" > server_template.info
        echo "cn = $domain" >> server_template.info
        echo "tls_www_server" >> server_template.info
        echo "encryption_key" >> server_template.info
        echo "signing_key" >> server_template.info
        echo "Entrez le nom de la clé privée (sans extention) [servkey.pem] : "
        read privkey
        if [ -z $privkey ]
        then
            privkey="servkey"
        fi
        certtool --generate-privkey > ${privkey}.pem
        echo "Entrez le chemin du certificat CA (/etc/pki/CA/cacert.pem) "
        read cacert
        if [ -z $cacert ]
        then
            cacert="/etc/pki/CA/cacart.pem"
        fi
        echo "Entrez le chemin de la clé privée du certificat CA (/etc/pki/CA/cakey.pem) "
        read cakey
        if [ -z $cakey ]
        then
            cakey="/etc/pki/CA/cakey.pem"
        fi
        echo "Entrez le nom du certificat serveur (avec extension) [servcert.pem] : "
        read servcert
        if [ -z $servcert ]
        then
            servcert="servcert.pem"
        fi
        echo "Génération du certificat serveur"
        certtool --generate-certificate \
                 --template server_template.info \
                 --load-privkey ${privkey}.pem \
                 --load-ca-certificate ${cacert} \
                 --load-ca-privkey ${cakey} \
                 --outfile ${servcert}
        rm server_template.info
        echo "Faut-il l'installer ? (O ou N)"
        read install
        if [ "$install" = "O" ] || [ "$install" = "o" ]
        then
            echo "Où ça (certificat) ? (/etc/ssl/certs) "
            read destcert
            echo "Où ça (clé privée) ? (/etc/ssl/private) "
            read destkey
            if [ -z $destcert ]
            then
                destcert="/etc/ssl/certs"
            fi
            if [ -z $destkey ]
            then
                destkey="/etc/ssl/private"
            fi
            if [ ! -d $destcert ]
            then
                sudo mkdir -p $destcert
            fi
            if [ ! -d $destkey ]
            then
                sudo mkdir -p $destkey
            fi
            sudo mv ${privkey}.pem $destkey/${privkey}.pem
            sudo mv ${servcert} $destcert/${servcert}
            sudo chmod 440 $destkey/${privkey}.pem $destcert/${servcert}
            echo "Certificat et clé privée installés dans $destcert/$servcert et $destkey/${privkey}.pem"
        fi
    elif ([ "$choice" = "C" ] || [ "$choice" = "c" ])
    then
        echo "Génération de certificat client pour un serveur"
        echo "Entrez un code de pays (FR) : "
        read country
        if [ -z $country ]
        then
            country="FR"
        fi
        echo "Entrez un nom de région/état (France) : "
        read state
        if [ -z $state ]
        then
            state="France"
        fi
        echo "Entrez un nom de localité (NONE) : "
        read locality
        if [ -z $locality ]
        then
            locality="NONE"
        fi
        echo "Entrez un nom d'organisation : "
        read org
        while [ -z $org ]
        do
            echo "Entrez un nom d'organisation : "
            read org
        done
        echo "Entrez un nom de domaine (client) : "
        read domain
        while [ -z $domain ]
        do
            echo "Entrez un nom de domaine (client) : "
            read domain
        done
        echo "country = $country" >> client_template.info
        echo "state = $state" >> client_template.info
        echo "locality = $locality" >> client_template.info
        echo "organization = $org" >> client_template.info
        echo "cn = $domain" >> client_template.info
        echo "tls_www_client" >> client_template.info
        echo "encryption_key" >> client_template.info
        echo "signing_key" >> client_template.info
        echo "Entrez le nom de la clé privée (sans extension) [clientkey.pem] :"
        read privkey
        if [ -z $privkey ]
        then
            privkey="clientkey"
        fi
        certtool --generate-privkey > ${privkey}.pem
        echo "Entrez le chemin du certificat CA (/etc/pki/CA/cacert.pem) "
        read cacert
        if [ -z $cacert ]
        then
            cacert="/etc/pki/CA/cacart.pem"
        fi
        echo "Entrez le chemin de la clé privée du certificat CA (/etc/pki/CA/cakey.pem) "
        read cakey
        if [ -z $cakey ]
        then
            cakey="/etc/pki/CA/cakey.pem"
        fi
        echo "Entrez le nom du certificat client (avec extension) [clientcert.pem] : "
        read clientcert
        if [ -z $clientcert ]
        then
            clientcert="clientcert.pem"
        fi
        echo "Génération du certificat client"
        certtool --generate-certificate \
                 --template server_template.info \
                 --load-privkey ${privkey}.pem \
                 --load-ca-certificate ${cacert} \
                 --load-ca-privkey ${cakey} \
                 --outfile ${clientcert}
        rm client_template.info
        echo "Faut-il l'installer ? (O ou N)"
        read install
        if [ "$install" = "O" ] || [ "$install" = "o" ]
        then
            echo "Où ça (certificat) ? (/etc/ssl/certs) "
            read destcert
            echo "Où ça (clé privée) ? (/etc/ssl/private) "
            read destkey
            if [ -z $destcert ]
            then
                destcert="/etc/ssl/certs"
            fi
            if [ -z $destkey ]
            then
                destkey="/etc/ssl/private"
            fi
            if [ ! -d $destcert ]
            then
                sudo mkdir -p $destcert
            fi
            if [ ! -d $destkey ]
            then
                sudo mkdir -p $destkey
            fi
            sudo mv ${privkey}.pem $destkey/${privkey}.pem
            sudo mv ${clientcert} $destcert/${clientcert}
            sudo chmod 440 $destkey/${privkey}.pem $destcert/${clientcert} 
        fi
    elif ([ "$choice" = "D" ] || [ "$choice" = "d" ])
    then
        echo "Génération de certificat auto-signé pour un serveur"
        echo "Entrez un code de pays (FR) : "
        read country
        if [ -z $country ]
        then
            country="FR"
        fi
        echo "Entrez un nom de région/état (France) : "
        read state
        if [ -z $state ]
        then
            state="France"
        fi
        echo "Entrez un nom de localité (NONE) : "
        read locality
        if [ -z $locality ]
        then
            locality="NONE"
        fi
        echo "Entrez un nom d'organisation : "
        read org
        while [ -z $org ]
        do
            echo "Entrez un nom d'organisation : "
            read org
        done
        echo "Entrez un nom commun pour votre service (client) : "
        read domain
        while [ -z $domain ]
        do
            echo "Entrez un nom commun pour votre service (client) : "
            read domain
        done
        echo "Entrez un nom de domaine pour votre certificat (aucun) : "
        read dnsname
        echo "Voulez-vous rajouter un nom de domaine (O ou N) : "
        read add_dns
        echo "dns_name = \"$add_dns\"" >> client_template.info
        while [ $add_dns = "O" ] || [ $add_dns = "o" ]
        do
            echo "dns_name = \"$add_dns\"" >> client_template.info
            echo "Voulez-vous rajouter un nom de domaine (O ou N) : "
            read add_dns
        done
        echo "country = $country" >> client_template.info
        echo "state = $state" >> client_template.info
        echo "locality = $locality" >> client_template.info
        echo "organization = $org" >> client_template.info
        echo "cn = $domain" >> client_template.info
        echo "tls_www_client" >> client_template.info
        echo "encryption_key" >> client_template.info
        echo "Entrez le nom de la clé privée (sans extension) [clientkey.pem] :"
        read privkey
        if [ -z $privkey ]
        then
            privkey="clientkey"
        fi
        certtool --generate-privkey > ${privkey}.pem
        echo "Entrez un nom pour votre certificat (client_cert.pem) : "
        read client_cert
        if [ -z $client_cert ]
        then
            $client_cert = "client_cert.pem"
        fi
        certtool --generate-self-signed --load-privkey ${privkey}.pem --template client_template.info --outfile $client_cert
        rm client_template.info
        echo "Faut-il l'installer ? (O ou N)"
        read install
        if [ "$install" = "O" ] || [ "$install" = "o" ]
        then
            echo "Où ça (certificat) ? (/etc/ssl/certs) "
            read destcert
            echo "Où ça (clé privée) ? (/etc/ssl/private) "
            read destkey
            if [ -z $destcert ]
            then
                destcert="/etc/ssl/certs"
            fi
            if [ -z $destkey ]
            then
                destkey="/etc/ssl/private"
            fi
            if [ ! -d $destcert ]
            then
                sudo mkdir -p $destcert
            fi
            if [ ! -d $destkey ]
            then
                sudo mkdir -p $destkey
            fi
            sudo mv ${privkey}.pem $destkey/${privkey}.pem
            sudo mv ${client_cert} $destcert/${client_cert}
            sudo chmod 440 $destkey/${privkey}.pem $destcert/${client_cert}
            echo "Certificat et clé privée installés dans $destcert/$client_cert et $destkey/${privkey}.pem"
        fi
    else
        echo "Stop writing shit and give a correct choice"
    fi
else
    echo "certtool du package gnutls est nécéssaire pour ce script"
    echo "Veuillez l'installer"
fi
