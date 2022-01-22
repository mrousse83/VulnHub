
# The Planets : Earth par SirFlash

Sur cette machine décrite comme facile mais un peu plus complexe que Mercury, il faut trouver un flag user et un flag root qui contiennent chacun un hash MD5.

## Analyse
Je vais dans un premier temps récupérer l'adresse IP de la machine virtuelle puis analyser celle-ci dans le but de trouver un point d'entrée.

### Recherche de l'adresse IP de la machine virtuelle
Pour récupérer l'adresse IP de la machine virtuelle, j'exécute la commande ```sudo netdiscover -i eth1 -r 192.168.56.0/24``` et je récupère son adresse : 192.168.56.102

### Recherche d'un point d'entrée
Je commence ma recherche afin de trouver un point d'entrée.
