

# Challenge Name

Ransomware


# Category

Forensics


# Challenge Prompt/Question


Some petty criminal named Axel Brosef installed ransomware on the Gotham National Bank and wants $1 million to unlock their files. GNB turned over a sample of the locked files to the Gotham Police Department. Use you forensicator skills to help the GPD break AxeBro's grip on the bank.




# Hints


If the challenge is too difficult any of these hints should help the challengers and can be released depending on where they are during their exploit development or where they are stuck.

* __Hint 1:__ *(patterns)* See any patterns in the raw file?
* __Hint 2:__ *(magic numbers)* Can you match any partial magic numbers?


# Key

flag{yoo_r_f0rensicksmeister}




# Walkthrough
Upon initial examination, the file appears to be encrypted and salted. Using a tool like byte-stats.py from Didier Stevens, the investigator will discover that the file has a low entropy point but overall high entropy, indicative of a weakness. The encrypted portion of the file is repeated 6 times; stripping that away will reveal the point of low entropy. This is a JPG file that has been stripped of the first 8 bytes of its header (the IF of JFIF is still visible). Prepend the missing header bytes to the image file to reveal the flag.


# References
https://isc.sans.edu/forums/diary/Ransomware+Entropy/20271/
http://osxdaily.com/2012/01/30/encrypt-and-decrypt-files-with-openssl/
https://en.wikipedia.org/wiki/List_of_file_signatures
http://unix.stackexchange.com/questions/6852/best-way-to-remove-bytes-from-the-start-of-a-file
