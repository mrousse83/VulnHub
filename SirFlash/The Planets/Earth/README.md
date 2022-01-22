
# The Planets : Earth par SirFlash

Sur cette machine décrite comme facile, il faut trouver un flag user et un flag root qui contiennent chacun un hash MD5.

## Analyse

Je commence par rechercher l'adresse IP de la VM avec la commande suivante :
```console
┌──(kali㉿kali)-[~]
└─$ sudo netdiscover -i eth1 -r 192.168.56.0/24
```

Elle me donne le résultat suivant :
```console
 Currently scanning: 192.168.56.0/24   |   Screen View: Unique Hosts
 
 3 Captured ARP Req/Rep packets, from 3 hosts.   Total size: 180
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
 -----------------------------------------------------------------------------
 192.168.56.1    0a:00:27:00:00:09      1      60  Unknown vendor
 192.168.56.100  08:00:27:9a:b9:05      1      60  PCS Systemtechnik GmbH
 192.168.56.102  08:00:27:e5:4c:fe      1      60  PCS Systemtechnik GmbH
```
L'adresse de la VM est donc : 192.168.56.102

