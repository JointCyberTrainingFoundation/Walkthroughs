

# Challenge Name

Across the Wire

# Points
100

# Category

Network Analysis 


# Challenge Prompt/Question

Several files were stolen from our customer, Big Bank Inc, and the files were wiped from their servers after exfil. One of the files contained a secret code and they need it back! We extracted traffic during the incident and need you to go in and extract the secret code. Good luck, Agent.




# Hints


If the challenge is too difficult any of these hints should help the challengers and can be released depending on where they are during their exploit development or where they are stuck.

* __Hint 1:__ *(try harder)* Maybe it's broken into chunks.


# Key

flag{the_tail_of_2_cities}


# Walkthrough
Each snapshot passed between nodes contains a summary of the files. When files are transferred between nodes, they're broken into chunks and mapped into a dictionary of hash:chunk. When the file "first_flag.txt" is transferred, the snapshot lists all the chunks that contain data for that file. Investigators need to find the mappings for the file (base64) and convert them back into a file. The flag is at the bottom of the reconstructed file. 


# References
N/A
