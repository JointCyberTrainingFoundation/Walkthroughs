

# Challenge Name

Celina Kyle


# Category

Web Exploitation 


# Challenge Prompt/Question

Criminal mastermind Celina Kyle from Gotham Labs Security suffers from amnesia. We've learned she stores her sensitive password to (IP address here) on a social media account, considering her skin-tight leather suit is not conducive for hiding notebooks. Find her password and log into the site!




# Hints


If the challenge is too difficult any of these hints should help the challengers and can be released depending on where they are during their exploit development or where they are stuck.

* __Hint 1:__ *(try harder)* She only uses two different user names. 
* __Hint 2:__ *(try harder)* She once mangled a man just to prohibit him from calling the cops. 



# Key

flag{1amst4lk1ngM315t3r}


# Walkthrough
Recon will lead competitors to her linkedin account https://www.linkedin.com/in/celinakyle or Twitter @celinakylesec (both link to each other)
Her username on the secret website is celinakyle, same as public linkedin account
The password is PROhibIT
PROHIBIT is a word in her provide. Users must build a dictionary of all words on the page
Incorrect guess will result in “Wrong password”
Using PROHIBIT as a guess will result in “Incorrect case sensitivity. Please check your CAPS LOCK key.” Users monitoring response sizes will notice the change and need to adapt their methodology at this point. 
Users will have to mangle PROHIBIT to find the real password


# References
N/A
