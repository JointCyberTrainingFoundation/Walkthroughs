# Challenge Name
LOBSTERFU

# Point Value and Assessed Difficulty
50

# Category
Reverse Engineering

# Challenge Prompt/Question
The trouble with lobsters is that they just don't want to hold still...

* [binary](link to binary)


# Hints

* __Hint 1:__ *(two kinds of RE)* This is an easy problem, but if you go about it the wrong way, it will probably take you longer.

# Key
LobstersMakeGreatDebuggers

# Walkthrough
This is an RE challenge that can be solved in a couple of ways, but dynamic RE is the easiest.

The easiest thing to do is to run the file and see what it does.  If you run it under strace, you'll see it trying to open a temp file and failing.

If you look at the error, you'll see it's because the file doesn't exist.  If you create the file, the program writes the flag there.

If you try to RE the binary, you'll see it's obfuscated (with llvm-obfuscator), at which point you should test some simple methods to see if you can get the flag without having to figure out the obfuscation.

If you did insist on doing static analysis, you might put together that the control flow is obfuscated and the key strings may be obfuscated, but the imports suggest that the only notable operations are file ops, and that you could do some quick debugger work to figure this out.

Using that knowledge, you could breakpoint on open() and write() to see if anything interesting is going on. You might conclude that since nothing of use is written to stdout, you could ignore write() until after open is called, which would lead you pretty quickly to the flag.  You could even modify the return of open() to get the flag printed to stdout.

## Concept Development
This came from the idea that folks may be good at static reversing, but that it's important to switch methods if one way is not looking like the right way to get the answer.  Other than that, it's just a simple dynamic linux RE problem.

## Discovery
    1. Notice this file is obfuscated
    2. Try dynamic methods
    3. Discover that it tries to open a file but fails, so make it so it doesn't.
    4. Profit


## Solution
Make the directory /tmp/82345123/ and put a file named 777 in it.  Run the binary and then cat the file for the flag.

If you use peda as your gdbinit, you could get a pretty slick experience like the one below.[1](#endnote1)

```
$ gdb lobsterfu
[...snip...]

gdb-peda$ b open
Breakpoint 1 at 0x8048420

gdb-peda$ r
Starting program: /home/user/code/jctf/llvm-obfuscator/lobsterfu/lobsterfu 
[----------------------------------registers-----------------------------------]
EAX: 0x1 
EBX: 0xffff0100 --> 0x0 
ECX: 0xffffc6c4 ("/tmp/82345123/777")
EDX: 0xffff0001 --> 0x0 
ESI: 0xcd48103b 
EDI: 0x0 
EBP: 0xffffcdb8 --> 0xffffceb8 --> 0xffffcfd8 --> 0xffffd208 --> 0x0 
ESP: 0xffffc5fc --> 0x804c74a (add    esp,0x10)
EIP: 0xf7ee1740 (<open>:    cmp    DWORD PTR gs:0xc,0x0)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0xf7ee173a:  xchg   ax,ax
   0xf7ee173c:  xchg   ax,ax
   0xf7ee173e:  xchg   ax,ax
=> 0xf7ee1740 <open>:   cmp    DWORD PTR gs:0xc,0x0
   0xf7ee1748 <open+8>: jne    0xf7ee176c <open+44>
   0xf7ee174a <open+10>:    push   ebx
   0xf7ee174b <open+11>:    mov    edx,DWORD PTR [esp+0x10]
   0xf7ee174f <open+15>:    mov    ecx,DWORD PTR [esp+0xc]
[------------------------------------stack-------------------------------------]
0000| 0xffffc5fc --> 0x804c74a (add    esp,0x10)
0004| 0xffffc600 --> 0xffffc6c4 ("/tmp/82345123/777")
0008| 0xffffc604 --> 0x1 
0012| 0xffffc608 --> 0x18 
0016| 0xffffc60c --> 0xffffc760 --> 0x0 
0020| 0xffffc610 --> 0x33 ('3')
0024| 0xffffc614 --> 0x0 
0028| 0xffffc618 --> 0xffffc630 --> 0x1d 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0xf7ee1740 in open () from /lib/i386-linux-gnu/libc.so.6

gdb-peda$ finish
Run till exit from #0  0xf7ee1740 in open () from /lib/i386-linux-gnu/libc.so.6
[----------------------------------registers-----------------------------------]
EAX: 0xffffffff 
EBX: 0xffff0100 --> 0x0 
ECX: 0xf7e068fc --> 0x2 
EDX: 0x18 
ESI: 0xcd48103b 
EDI: 0x0 
EBP: 0xffffcdb8 --> 0xffffceb8 --> 0xffffcfd8 --> 0xffffd208 --> 0x0 
ESP: 0xffffc600 --> 0xffffc6c4 ("/tmp/82345123/777")
EIP: 0x804c74a (add    esp,0x10)
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804c737:   mov    DWORD PTR [esp+0x4],0x1
   0x804c73f:   mov    DWORD PTR [ebp-0x264],eax
   0x804c745:   call   0x8048420 <open@plt>
=> 0x804c74a:   add    esp,0x10
   0x804c74d:   mov    ecx,0x73419441
   0x804c752:   mov    edx,0x9b579628
   0x804c757:   mov    bl,0x1
   0x804c759:   xor    esi,esi
[------------------------------------stack-------------------------------------]
0000| 0xffffc600 --> 0xffffc6c4 ("/tmp/82345123/777")
0004| 0xffffc604 --> 0x1 
0008| 0xffffc608 --> 0x18 
0012| 0xffffc60c --> 0xffffc760 --> 0x0 
0016| 0xffffc610 --> 0x33 ('3')
0020| 0xffffc614 --> 0x0 
0024| 0xffffc618 --> 0xffffc630 --> 0x1d 
0028| 0xffffc61c --> 0x80482a9 ("memset")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804c74a in ?? ()

gdb-peda$ set $eax=1
gdb-peda$ c
Continuing.
LobstersMakeGreatDebuggers
                              ,.---.   
                    ,,,,     /    _ `.
                     \\\\   /      \  )
                      |||| /\/``-.__\/
                      ::::/\/_
      {{`-.__.-'(`(^^(^^^(^ 9 `.========='
     {{{{{{ { ( ( (  (   (-----:=
      {{.-'~~'-.(,(,,(,,,(__6_.'=========.
                      ::::\/\ 
                      |||| \/\  ,-'/\
                     ////   \ `` _/  )
                    ''''     \  `   /
jgs                            `---''

30326813
[Inferior 1 (process 19853) exited normally]
Warning: not running or target is remote
gdb-peda$ 
```

----

# Endnotes

<a name="endnote1">[1]</a>: The easiest way to make your gdb experience better is to use a good gdbinit file, such as [peda](https://github.com/longld/peda)
