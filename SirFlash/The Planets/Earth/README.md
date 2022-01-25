
# The Planets : Earth par SirFlash

Sur cette machine virtuelle décrite comme facile mais un peu plus complexe que Mercury, il faut trouver un flag user et un flag root qui contiennent chacun un hash MD5.

## Analyse
Je vais dans un premier temps récupérer l'adresse IP de la machine virtuelle puis analyser celle-ci dans le but de trouver un point d'entrée.

### Recherche de l'adresse IP de la machine virtuelle
Pour récupérer l'adresse IP de la machine virtuelle, j'exécute la commande ```sudo netdiscover -i eth1 -r 192.168.56.0/24``` et je récupère son adresse : 192.168.56.102

### Recherche d'un point d'entrée
Je commence ma recherche afin de trouver un point d'entrée.

#### Recherche avec nmap
Je lance une analyse avec la commande ```nmap -e eth1 -A -p- -T4 192.168.56.102``` :
```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-22 06:13 EST
Nmap scan report for 192.168.56.102
Host is up (0.00057s latency).
Not shown: 65371 filtered tcp ports (no-response), 161 filtered tcp ports (host-unreach)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.6 (protocol 2.0)
| ssh-hostkey: 
|   256 5b:2c:3f:dc:8b:76:e9:21:7b:d0:56:24:df:be:e9:a8 (ECDSA)
|_  256 b0:3c:72:3b:72:21:26:ce:3a:84:e8:41:ec:c8:f8:41 (ED25519)
80/tcp  open  http     Apache httpd 2.4.51 ((Fedora) OpenSSL/1.1.1l mod_wsgi/4.7.1 Python/3.9)
|_http-title: Bad Request (400)
|_http-server-header: Apache/2.4.51 (Fedora) OpenSSL/1.1.1l mod_wsgi/4.7.1 Python/3.9
443/tcp open  ssl/http Apache httpd 2.4.51 ((Fedora) OpenSSL/1.1.1l mod_wsgi/4.7.1 Python/3.9)
|_http-title: Test Page for the HTTP Server on Fedora
| http-methods: 
|_  Potentially risky methods: TRACE
| ssl-cert: Subject: commonName=earth.local/stateOrProvinceName=Space
| Subject Alternative Name: DNS:earth.local, DNS:terratest.earth.local
| Not valid before: 2021-10-12T23:26:31
|_Not valid after:  2031-10-10T23:26:31
|_http-server-header: Apache/2.4.51 (Fedora) OpenSSL/1.1.1l mod_wsgi/4.7.1 Python/3.9
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 187.23 seconds
```

Je constate qu'il y a 3 ports ouverts :
* 22/tcp (ssh) : OpenSSH 8.6 (protocol 2.0)
* 80/tcp (http) : Apache httpd 2.4.51 ((Fedora) OpenSSL/1.1.1l mod_wsgi/4.7.1 Python/3.9)
* 443/tcp (ssl/http) : Apache httpd 2.4.51 ((Fedora) OpenSSL/1.1.1l mod_wsgi/4.7.1 Python/3.9)

Le certificat SSL contient également deux noms DNS :
* earth.local
* terratest.earth.local

J'ajoute ces deux noms DNS dans mon fichier ```/etc/hosts``` :
```
192.168.56.102 earth.local terratest.earth.local
```

### Analyse du port 80 et 443
Je lance un ```dirb http://earth.local``` et un ```dirb https://earth.local``` qui me permet de trouver la page ```https://earth.local/admin``` qui contient un lien vers la page ```http://earth.local/admin/login```.
Puis un ```dirb http://terratest.earth.local``` et un ```dirb https://terratest.earth.local``` qui me permet de trouver le fichier ```https://terratest.earth.local/robots.txt``` qui contient :
```
User-Agent: *
Disallow: /*.asp
Disallow: /*.aspx
Disallow: /*.bat
Disallow: /*.c
Disallow: /*.cfm
Disallow: /*.cgi
Disallow: /*.com
Disallow: /*.dll
Disallow: /*.exe
Disallow: /*.htm
Disallow: /*.html
Disallow: /*.inc
Disallow: /*.jhtml
Disallow: /*.jsa
Disallow: /*.json
Disallow: /*.jsp
Disallow: /*.log
Disallow: /*.mdb
Disallow: /*.nsf
Disallow: /*.php
Disallow: /*.phtml
Disallow: /*.pl
Disallow: /*.reg
Disallow: /*.sh
Disallow: /*.shtml
Disallow: /*.sql
Disallow: /*.txt
Disallow: /*.xml
Disallow: /testingnotes.*
```

Cette dernière liste semble intéressante.

En essayant quelques extensions, je trouve rapidement la présence du fichier ```https://terratest.earth.local/testingnotes.txt``` dont voici son contenu :
```
Testing secure messaging system notes:
*Using XOR encryption as the algorithm, should be safe as used in RSA.
*Earth has confirmed they have received our sent messages.
*testdata.txt was used to test encryption.
*terra used as username for admin portal.
Todo:
*How do we send our monthly keys to Earth securely? Or should we change keys weekly?
*Need to test different key lengths to protect against bruteforce. How long should the key be?
*Need to improve the interface of the messaging interface and the admin panel, it's currently very basic.
```
