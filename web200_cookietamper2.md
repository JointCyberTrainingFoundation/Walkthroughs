

# Challenge Name

Sharing Secrets Pt 2

# Points
200

# Category

Web Exploitation 


# Challenge Prompt/Question

Break into the secret sharing website (IP: address here) to access the villian Pain's account. Through intelligence gathering, we have learned that his username is 'pain'.




# Hints


If the challenge is too difficult any of these hints should help the challengers and can be released depending on where they are during their exploit development or where they are stuck.

* __Hint 1:__ *(try harder)* Try making long accounts with similar patterns.



# Key

flag{f33l_mypain11111}


# Walkthrough
Same problem as Web1, but attacker must forge login for 'pain'
Attacker must manually discover the server secret
7chars+s == login
6chars+su== login
5chars+sup==login
pain+supe == login
cookie: ebd555acecf09b3c034874fe368fb52b&pain


# References
N/A
