

# Challenge Name

house_of_keys

# Point Value and Assessed Difficulty

200 Medium

# Category

Cryptography

# Challenge Prompt/Question

A Crypto challenge

> Reports that say that something hasn't happened are always interesting to me, because as we know, there are known knowns; there are things we know we know. We also know there are known unknowns; that is to say we know there are some things we do not know. But there are also unknown unknowns – the ones we don't know we don't know. And if one looks throughout the history of our country and other free countries, it is the latter category that tend to be the difficult ones.

The question is what category is needed here?




* [pcap](dump.pcap)


# Hints

* __Hint 1:__ *(crypto)* Think IoT vulnerability.
* __Hint 2:__ *(link)* [House of Keys](http://blog.sec-consult.com/2015/11/house-of-keys-industry-wide-https.html)
* __Hint 3:__ *(recon)* All these connected devices, they are like little black boxes to me!
* __Hint 4:__ *(link)* [little-black-box](https://github.com/chrisprice/little-black-box)
* ...

# Key

flag{hard_coded_ssh_keys_fail}

# Walkthrough

This challenge requires a bit of recon, a bit of forensics and some crypto.  To solve this challenge, the attacker must realize that this traffic was encrypted with known SSL keys, which is a weakness of IoT devices as their keys can be hard coded into the firmware.

## Concept Development

Encryption fails most often due to human error.  This challenge highlights a common error that non-security savy people make when configuring devices, especially home routers.

## Discovery

1. Reconize SSL traffic in PCAP file, 
2. Search for 'house of keys' or 'known ssl keys' [\[1\]](#endnote1)
3. Filter pcap for SSL Certificates `ssl.handshake.type == 11`
4. Find one certificate from a private IP, save the certificate as 'cert.der'


## Solution

----

1. Once you have the exported certificate, its time to get the private key and decrypt traffic. 
2. Get the fingerprint for the certificate with  
 `openssl x509 -inform DER -in cert.pem.bin -fingerprint` 
3. Use littleblackbox to search the pcap file for a match. 
 `littleblackbox  -pcap=dump.pcap -f 20:C6:9B:D1:34:44:46:07:19:EF:39:C3:5E:C3:D1:18:4C:88:0A:0B` 
4. Add the private key to Wireshark to decrypt the SSL traffic. 
    * Edit menu, then Preferences
    * Protocols, then SSL
    * 'Edit' the RSA keys list
    * Add the private key for 192.168.11.254, port 443, protocol http
5. Find a HTTP GET request with basic authentiation. `http.authbasic`


----

# Endnotes

<a name="endnote1">[1]</a>: https://nmap.org/nsedoc/scripts/ssl-known-key.html
