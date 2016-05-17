# Challenge Name
Ancient Armament

# Point Value and Assessed Difficulty
100

# Category
Reverse Engineering

# Challenge Prompt/Question
When your code really has to work, you apparently make it a huge pain to write.  And somehow that helps.

But hey, it's not just your dad's programming language, it beat out 16 competing proposals to be your dad's programming language.

* [binary](link to binary)

# Hints

* __Hint 1:__ *(try a debugger)*  This isn't that big of a binary, so you should be able to identify key procedures by looking at it in a debugger

# Key
flag{http://xkcd.com/297/}

# Walkthrough
Starting by dropping this Ida, we can see that it's not a "normal looking binary", but we get put at the main function, "_main".  Seeing references to ada might make us believe it was written in Ada and compiled in an Ada compiler, but that's only really useful for understanding the binary isn't obfuscated, it was just born bad.[1](#endnote1)

A quick poke through the functions _main calls or looking at string references shows the function "__ada_throwback" to really be the part we're interested in, and is more likely the "true main" of the program.

Running the program, we can see that there are three times the user is prompted for input, and glancing near the bottom we can see some string references that seem to indicate success or failure.

If we start by looking at the branchees that begin to happen after the third user input, we can see there is a comparison of the return value of "_ada__strings__unbounded__length" to 0x1A (26), and we can confirm that it is indeed comparing the length of our third input to 26 and if they don't match, we get output that suggests failure.

If we try an input of 26 A's, we pass that check and enter what appears to be a loop (initialization of two variables with 1 and the aforementioned length, plus a blue arrow coming in from a basic block near the bottom that increments the variable just initialized to 1 is a good hint).

The first thing we can see is a call to "_ada__strings__unbounded__element" which returns the first character of our input from the third question.

After a bunch of checks, we can see some math being performed on the input character starting at address 0x401AFB.  Looking ahead a bit, we can see that there's basically two ways out, one continuing in the loop, and one not.  If we continue through, we can see that our inputs of all A's bails before looping even once, so this must be a character-by-character comparison to an expected value.

If we examine the math in the block at 0x401AFB, we can see that our current character gets two things added to it: 0x4d and the current value of the index variable (noting that it starts at 1).  It's then compared to a value that gets loaded at address 
0x401B30.

If we look at the address where the byte is loaded from, we can see what appears to be an array of bytes stored as 32-bit integers.  If we guess that this is an array of length 26 based on the required input length, we see that it is indeed.  We can then take the values in the array and reverse the math performed on our input and get the flag:

in python:
>>> flag=''
>>> for i in range(len(x)):
...  flag += chr(x[i] - (i+1) - 0x4d)
...
>>> flag
'flag{http://xkcd.com/297/}'

## Concept Development

The idea for using an old programming language isn't new to JCC, because many of the staff have been asked to use old programming languages for projects, and we believe there's something to be learned from each programming language.  Since this is a reversing problem, the biggest lesson here is how different compilers and languages can add checks that would seem random and/or redundant to someone used to looking at C code.  It also satisfies the curosity of those competitors who burn to know how Ada can be so "safe."

----

# Endnotes

<a name="endnote1">[1]</a>: Are you interested in programming in Ada? Take my advice and don't ever act on that.  If you must, check out the GNAT compiler, GPS IDE, and the [Ada Programming Wikibook](https://en.wikibooks.org/wiki/Ada_Programming) but don't say I didn't warn you.

