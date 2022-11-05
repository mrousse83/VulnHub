# Shadow Phreak - NoobBox

Pour cette machine de niveau débutant, l'auteur nous indique qu'il faut trouver 2 flags :
* un flag utilisateur
* un flag administrateur

Il nous indique également que sa machine fonctionne mieux sur VirtualBox que sur VMware.

## Recherche de l'adresse IP de la machine

L'adresse MAC de la carte réseau de ma machine s'exécutant sous VirtualBox commencera toujours par "08:00:27".  
Je lance donc la commande suivante :
```
sudo netdiscover | grep "08:00:27"
```
Elle me permet d'obtenir l'adresse IP de ma machine : `192.168.7.96    08:00:27:b0:7d:2d      1      60  PCS Systemtechnik GmbH`
