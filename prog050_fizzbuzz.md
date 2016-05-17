<!-- name this file 2016_JCC_CategoryName_ChallengeName.md -->

# Challenge Name
Effervescent Drone

# Point Value and Assessed Difficulty
50

# Category
Programming

# Challenge Prompt/Question
The classic test for fledgling programmers: fb.gameofpwn.es:61815

You get +3 Fonzie points if your solution works the first time.

# Hints
* __Hint 1:__ *(Help me help you)* Writing your own solution makes you a better programmer.  Prove you can do it yourself.

# Key
flag{You_can_now_get_a_job_writing_java}

# Walkthrough
For loops and modulo arithmetic, as well as the ability to google.

You could use netcat instead of sockets if sockets are too hard.

## Concept Development
This problem is considered a sanity check in programming interviews, and everybody who claims to know any scripting or programming should be able to solve it.


## Discovery

## Solution

----

# Proof of Exploit/Solution

```
from socket import *

SERVER="127.0.0.1"
PORT=0xf177
ceiling = 1000

s = socket()
s.connect((SERVER, PORT))
print s.recv(1000)


output = ""
for i in range(1, ceiling+1):
    ans = ""
    if (i % 3) == 0:
        ans += "Fizz"
    if (i % 5) == 0:
        if ans != "":
            ans += " "
        ans += "Buzz"
    if ans == "":
        ans = str(i)
    ans += ", "
    output += ans
output = output[:-2] + "\n"  # get rid of trailing ", "
#print output
s.send(output)
print(s.recv(1000))
```

----

# Endnotes

<a name="endnote1">[1]</a>: Wikipedia fizzbuzz article [here](https://en.wikipedia.org/wiki/Fizz_buzz)
