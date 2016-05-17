

# Challenge Name

RSA Token

# Points
125

# Category

Web Exploitation 
Recon
Forensics


# Challenge Prompt/Question

Criminal mastermind Celina Kyle doesn't have room in her skin-tight suit to store her RSA token. Instead, she setup a web cam to view her RSA token remotely. Through recovered intel, you find her username and password for the site (IP address here) to be celinakyle and cLeartExt4TW respectively. Because of her amnesia, she doesn't keep the token far away. Login to her server and steal her secret code.




# Hints


If the challenge is too difficult any of these hints should help the challengers and can be released depending on where they are during their exploit development or where they are stuck.

* __Hint 1:__ *(try harder)* Maybe there's another open port?
* __Hint 2:__ *(try harder)* Maybe it's a nonstandard open port?


# Key

flag{u_g00d_g_i}


# Walkthrough
Users must nmap all open ports on the target to find the non-standard port hosting a webserver. 

REST API server displays a base64 encoded version of the token on port 1025. Challenger must decode the file and use the tokenID and token to login. Easy.
Username: celinakyle
Password: cLeartExt4TW
RSA token ID: 52126244 
RSA token: 017404


# References
N/A
