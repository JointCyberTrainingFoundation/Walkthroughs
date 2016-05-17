

# Challenge Name

Sharing Secrets Pt 1

# Points
100

# Category

Web Exploitation 


# Challenge Prompt/Question

Break into the secret sharing website (IP: address here) to access the villian Poison Oak's account. Through intelligence gathering, we have learned that her username is 'poisonoak'.




# Hints


If the challenge is too difficult any of these hints should help the challengers and can be released depending on where they are during their exploit development or where they are stuck.

* __Hint 1:__ *(try harder)* Try making long accounts with similar patterns.



# Key

flag{c00kiecrush3rZ}


# Walkthrough
User needs to log into website as poisonoak. Server issues a cookie that uses crypt(username+server_secret) to confirm authenticated users. Crypt only uses the first 8 chars for input, so a user with a username longer than 8 chars never has cookie appended with server secret. Crypt(poisonoa) is the effective cookie value.
Allow users to create certain accounts at will and let them figure out the vuln
Users must forge a cookie for poisonoak to reveal flag
Cookie value: 9af72da568a36ee932114ef892ffb2dc&poisonoak


# References
N/A
