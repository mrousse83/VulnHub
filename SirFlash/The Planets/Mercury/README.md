# The Planets : Mercury par SirFlash

Cette machine virtuelle est décrite comme facile, elle ne nécessite pas de brute force. Il faut trouver un flag user et un flag root qui contiennent chacun un hash MD5.

Sommaire de cet article :
* [Analyse](#analyse)
  * [Recherche de l'adresse IP de la machine virtuelle](#recherche_ip)
  * [Recherche d'un point d'entrée](#recherche_pe)
    * [Recherche avec nmap](#recherche_nmap)

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

Avec la commande ```dirb http://192.168.56.103:8080``` je trouve la présence d'un fichier ```robots.txt``` mais celui-ci ne contient rien...

En voulant visiter l'adresse ```http://192.168.56.103:8080/admin```, j'arrive sur une page d'erreur me donnant des informations intéressantes :
```
Using the URLconf defined in mercury_proj.urls, Django tried these URL patterns, in this order:

    [name='index']
    robots.txt [name='robots']
    mercuryfacts/

The current path, admin, didn't match any of these.
```

