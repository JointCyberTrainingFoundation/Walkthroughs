# Challenge Name
Scramble

# Point Value and Assessed Difficulty
50

# Category
Network Exploitation / Miscellaneous / Scramble

# Challenge Prompt/Question
This is a unique problem, where you are given creds to a box, and so are all the other teams.

Your advon team has secured you sudoer access to execute two files as the target user.

One of the two is a secret weapon, scramble.sh, but we fear the enemy has tampered with it...

Find a way to get the flag before the other teams do!

# Hints

* __Hint 1:__ *(bash)* this problem comes with a bash binary in the current directory, which is probably not a coincidence
* __Hint 2:__ *(sudo)* you have sudoer access, but that's not root access.  There's a file on the system that contains the information on sudo rights.


# Key
flag{Sh0ck_4nd_4w3_m34ns_b31ng_Qu1ck_70_7h3_Punch}

# Walkthrough
scramble.sh is an obfuscated shell script that creates .surprise_attack, but its final line has an obfuscated "./bash --rcfile .surprise_attack" commented out, which makes scramble.sh a red herring at least for what it does.

scramble.sh's first line is #!./bash which causes it to be executed by the bash binary in the current directory, which is bash-4.2, an old version of bash

There are also mentions in the comments of scramble.sh of bash functions and environment variables, and googling bash functions and environment variables shows shellshock results in the top 10.  Following in this vein, the competitor should be able to find a way to invoke shellshock to "test" if the bash binary is vulnerable, and then use the vulnerability to read the flag file. [1](#endnote1)

## Concept Development
When the idea of a scramble problem was proposed, I thought of interesting and pertinent shell vulnerabilities.  Shellshock came to mind, and this problem was the result of figuring out how to get competitors to use the Shellshock vulnerability.

## Discovery
    1. Read shell files, notice bash binary being used
    2. Understand sudo access gives the challenger the ability to execute the file, and so any way to abuse that could lead to the flag
    3. Try to read the sudoers file to learn what possibilites are available
    4. Look up bash version for known vulnerabilities, find shellshock, use it to get the flag


## Solution

Invoke the script we have sudoer access to with some bash functions in the environment to leverage the ShellShock vulnerability to output the flag, as shown below.

----

# Proof of Exploit/Solution

```sh
sudo -u user2 env 'x=() { :;}; cat flag' ./scramble.sh
```

----

# Endnotes

<a name="endnote1">[1]</a>: RedHat put out an article with a command to test ShellShock [link](https://access.redhat.com/articles/1200223)
