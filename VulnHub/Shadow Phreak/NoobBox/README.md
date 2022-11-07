# Shadow Phreak - NoobBox

Pour cette machine de niveau débutant, l'auteur nous indique qu'il faut trouver 2 flags :
* un flag utilisateur
* un flag administrateur

Il nous indique également que sa machine fonctionne mieux sur VirtualBox que sur VMware.

# Analyse 

## Recherche de l'adresse IP de la machine

L'adresse MAC de la carte réseau de ma machine s'exécutant sous VirtualBox commencera toujours par "08:00:27".  
Je lance donc la commande suivante :
```
sudo netdiscover | grep "08:00:27"

192.168.7.96    08:00:27:b0:7d:2d      1      60  PCS Systemtechnik GmbH
```
Elle me permet d'obtenir l'adresse IP de ma machine : 192.168.7.96

## Recherche d'un point d'entrée

Je commence une première approche avec nmap :
```
sudo nmap -A 192.168.7.96 -p-

PORT   STATE    SERVICE VERSION
53/tcp filtered domain
80/tcp open     http    Apache httpd 2.4.38 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.38 (Debian)
```
Le point d'entrée sera donc le port 80.

Je visite le site web, il s'agit de la page par défaut d'Apache 2.

Je cherche ensuite s'il n'y a pas des répertoires cachés :
```
dirb http://192.168.7.96

==> DIRECTORY: http://192.168.7.96/wordpress/
```

Je découvre qu'il y a un site WordPress, son contenu ne contient rien d'intéressant.  
Je recherche s'il contient une faille :
```
wpscan --url http://192.168.7.96/wordpress/ -e u

[+] noobbox
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

Il ne contient pas de faille mais j'ai récupéré le nom d'utilisateur : noobbox  

