---
layout: post
title: IceCTF: Contract - cracking insecure ECDSA
date: 2016-08-26 17:25:00 +0200
summary: Short writeup of the contract task in IceCTF 2016
---



### IceCTF: Contract - cracking insecure ECDSA

> Our contractors stole the flag! They put it on their file server and challenged us to get it back. Can you do it for us? nc contract.vuln.icec.tf 6002 server.py. We did intercept someone connecting to the server though, maybe it will help. contract.pcapng 

You may view the server.py [here](https://github.com/simenbkr/CTFs/blob/master/IceCTF/contract/server.py) and the pcap [here](https://github.com/simenbkr/CTFs/blob/master/IceCTF/contract/contract_21a39e102f0edb8f55c7e54e22e71ae53c9dc94163844cf04b651ad02ac4fb7d.pcapng?raw=true)

In this task we are given the server sourcecode with the ECC public key and a pcap-file with two connections to the server. These two connections have both sent a command with a valid signature.

Here is the relevant info from the pcaps:

>time:c0e1fc4e3858ac6334cc8798fdec40790d7ad361ffc691c26f2902c41f2b7c2fd1ca916de687858953a6405423fe156c0cbebcec222f83dc9dd5b0d4d8e698a08ddecb79e6c3b35fc2caaa4543d58a45603639647364983301565728b504015d

>help:c0e1fc4e3858ac6334cc8798fdec40790d7ad361ffc691c26f2902c41f2b7c2fd1ca916de687858953a6405423fe156cfd7287caf75247c9a32e52ab8260e7ff1e46e55594aea88731bee163035f9ee31f2c2965ac7b2cdfca6100d10ba23826


And here is the public key:

```-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEgTxPtDMGS8oOT3h6fLvYyUGq/BWeKiCB
sQPyD0+2vybIT/Xdl6hOqQd74zr4U2dkj+2q6+vwQ4DCB1X7HsFZ5JczfkO7HCdY
I7sGDvd9eUias/xPdSIL3gMbs26b0Ww0
-----END PUBLIC KEY-----


Decoding the public key using OpenSSL:

```root@kali:~/icectf/contract# openssl asn1parse -in pub
    0:d=0  hl=2 l= 118 cons: SEQUENCE          
    2:d=1  hl=2 l=  16 cons: SEQUENCE          
    4:d=2  hl=2 l=   7 prim: OBJECT            :id-ecPublicKey
   13:d=2  hl=2 l=   5 prim: OBJECT            :secp384r1
   20:d=1  hl=2 l=  98 prim: BIT STRING
   

The important information to see here is the secp384r1-string.

>secp384r1 : NIST/SECG curve over a 384 bit prime field

This is the elliptic curve used by the crypto used. (Learn more about elliptic curve cryptography [1]

The observant reader will have noted that both signatures begins with the same (17.5) bytes:

> c0e1fc4e3858ac6334cc8798fdec40790d7

This is a common error in the ECDSA scheme. Honestly I don't know enough about it to explain properly, but much of the understanding is "borrowed" from https://antonio-bc.blogspot.no/2013/12/mathconsole-ictf-2013-writeup.html.

The error is in the generation of the signatures where a nonce is repeated. This allows for us, the attackers, to recover the private key.

```python
#Credit for this goes to [2]
def recover_key(c1,sig1,c2,sig2,pubkey):
      #using the same variable names as in:
      #http://en.wikipedia.org/wiki/Elliptic_Curve_DSA

      curve_order = pubkey.curve.order

      n = curve_order
      s1 = string_to_number(sig1[-48:])
      print "s1: " + str(s1)
      s2 = string_to_number(sig2[-48:])
      print "s2: " + str(s2)
      r = string_to_number(sig1[-96:--48])
      print "r: " + str(r)
      print "R values match: " + str(string_to_number(sig2[-96:--48]) == r)

      z1 = string_to_number(sha256(c1))
      z2 = string_to_number(sha256(c2))

      sdiff_inv = inverse_mod(((s1-s2)%n),n)
      k = ( ((z1-z2)%n) * sdiff_inv) % n
      r_inv = inverse_mod(r,n)
      da = (((((s1*k) %n) -z1) %n) * r_inv) % n

      print "Recovered Da: " + hex(da)

      recovered_private_key_ec = SigningKey.from_secret_exponent(da, curve=NIST384p)
      return recovered_private_key_ec.to_pem()
```

Giving us the private key:

```-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDD+qZQfEucEMokaAWn0wrTsPz3nMwIlBasVdyQpi/zT3X7UdF7WDD23
EChyxQOSWMigBwYFK4EEACKhZANiAASBPE+0MwZLyg5PeHp8u9jJQar8FZ4qIIGx
A/IPT7a/JshP9d2XqE6pB3vjOvhTZ2SP7arr6/BDgMIHVfsewVnklzN+Q7scJ1gj
uwYO9315SJqz/E91IgveAxuzbpvRbDQ=
-----END EC PRIVATE KEY-----```

which in turns allows for us to send in the command read flag.txt with a valid signature.

```python
command = b'read flag.txt'

sk = SigningKey.from_pem(PRIVATE_KEY.strip())
signature = hexlify(sk.sign(command,hashfunc=hashlib.sha256))

command = command+b':'+signature
print command


r = remote('contract.vuln.icec.tf',6002)
sleep(0.1)
r.send(command+'\n')
r.interactive()
r.close()
```


Scripts can be found here: [solve.py](https://github.com/simenbkr/CTFs/blob/master/IceCTF/contract/solve.py) and [kok.py](https://github.com/simenbkr/CTFs/blob/master/IceCTF/contract/kok.py)

Resources for further reading:

[1] https://blog.cloudflare.com/a-relatively-easy-to-understand-primer-on-elliptic-curve-cryptography/

[2] https://neg9.org/news/2015/8/12/openctf-2015-veritable-buzz-1-crypto-300-writeup

[3] https://antonio-bc.blogspot.no/2013/12/mathconsole-ictf-2013-writeup.html

