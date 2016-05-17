## Challenge name
Shrek


### Point Value and Assessed Difficulty
250	Medium

### Category
Reverse Engineering

### Challenge Prompt/Question
A reversing challenge binary with layers.

>Shrek: Ogres are like onions.  
>Donkey: They stink?  
>Shrek: Yes. No.  
>Donkey: Oh, they make you cry.  
>Shrek: No.  
>Donkey: Oh, you leave em out in the sun, they get all brown, start sproutin' little white hairs.  
>Shrek: NO. Layers. Onions have layers. Ogres have layers. Onions have layers. You get it? We both have layers.  
>Donkey: Oh, you both have layers. Oh. You know, not everybody like onions. 


* [binary](shrek)

### Hints
* __Hint 1:__ *(general)* the layers refer the multiple levels of unpacking
* __Hint 2:__ *(tool)* IDA Python could be your best friend
* ...

### Key
flag{_On10ns_aRe_a_ta57y_tR3a7_}

### Walkthrough
This challange requires either some finesse and patience with GDB or skills in IDA Pro.  First you need to recognize the call to mprotect to make the text section writable, then pull out the XOR keys and to unpack each layer.  Additionally, simple obfucation techniques have been added to throw off native disassembly methods.

### Concept Development
Malware authors take extreme measures to protect their binaries from reverse engineering and even legitimate software developers use obsfucation techniques to protect their code.  This challenge provides some simple obsfucation techniques that must be overcome in order to expose the flag.

### Discovery

1. Since this is a reversing challenge, starting with strings would be appropriate.  In the strings output we see a message that will be displayed when we have found the key, but nothing that looks like a key.
2. We can start by examing the binary with objdump.  In the function main we see calls to `prep-the-objective` and `auth`.  The function prep-the-objective calls mprotect and sets a page of memory to writable, the page of memory that includes the auth function. 
3. Upon examing the function auth, we can tell that something is not right.  The disassembly of the function auth quickly begins to look like jibberish with several byte sequences yielding 'bad' instructions.
4. At this point, we can attempt to walk the program execution in GDB.  

### Solution

The solution to the challenge is finding the input that this program accepts.  Once the assembly is de-obsfucated, the key will be in plain sight!

----

First we find a chunk of code upon entering the function 'auth' like this:

```assembly
.text:08048464 loc_8048464:                            ; CODE XREF: .text:08048461j
.text:08048464                 lea     eax, loc_804847F
.text:0804846A
.text:0804846A loc_804846A:                            ; CODE XREF: .text:08048479j
.text:0804846A                 cmp     dword ptr [eax], 4030201h
.text:08048470                 jz      short loc_804847F
.text:08048472                 xor     dword ptr [eax], 7788h
.text:08048478                 inc     eax
.text:08048479                 jmp     short loc_804846A
```

An IDA Python script to decrypt this block of code.  The start, stop and key must be modified for every chunk.

```python
ea = get_name_ea(BADADDR,'loc_804847F')
stop = pack('<L',0x04030201)
key = pack('<H',0x7788)
while get_many_bytes(ea,4) != stop:
  buf = get_many_bytes(ea,2)
  b1 = chr(ord(buf[0]) ^ ord(key[0]))
  b2 = chr(ord(buf[1]) ^ ord(key[1]))
  buf = b1+b2
  patch_many_bytes(ea, buf)
  ea += 1
```

Once all the chunks have been decrypted, this script will pull out all the letters to the flag!

```python
ea = get_name_ea(BADADDR,'auth')
l = []
while (ea < 0x8048b50):
  ea = idc.NextHead(ea)
  if GetMnem(ea) == "cmp" and GetOpnd(ea,0) == "al":
    l.append( chr(GetOperandValue(ea,1)) )
print ''.join(l)
```
----

## Endnotes
<a name="endnote1">[1]</a>: Link to an endnote if you need it. It's best to use this for references with your walkthrough.
