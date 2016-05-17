# Challenge Name
MOVFU

# Point Value and Assessed Difficulty
400

# Category
Reverse Engineering

# Challenge Prompt/Question
I like lobsters and all, but when it comes to x86 instructions, there's one I love best.

I hope you love it too.

* [binary](link to binary)

# Hints

* __Hint 1:__ *(problem structure)* The binary doesn't take any input, so it must contain or expose the flag somehow
* __Hint 2:__ *(runtime strings)* You might have to come up with a way to figure out when a string gets deobfuscated at run-time and dump it

# Key
MovIsTuringComplete

# Walkthrough
This binary is obfuscated with movfuscator (https://github.com/xoreaxeaxeax/movfuscator).[1](#endnote1)  It's a bear.

The binary has symbols, you can see there's a decrypt function, which logic would lead us to think decrypts the key in memory, which it does indeed.  Other hints include the fact the binary doesn't act any differently regardless of what arguments it's called with, it doesn't ask for input, and it doesn't import any interesting API fuctions.

The trick is knowing where this happens and what register points to the string.  There's a few ways to do this, and with such a difficult obfuscation, any way is a legitimate way.

I wrote a python script that steps gdb through executing the program and tests to see if each register points to a string.  If it does, it saves that to a file.  Running this script takes less than 25 seconds on my machine, and at the end I have all the strings that any register pointed to, and it's fairly obvious which one is the flag as there aren't many unique strings in this binary's excecution.

## Concept Development
Movfuscator is an awesome idea, and a great example of straightforward but difficult-to-deal-with obfuscation.  It forces competitors to step back from static reversing and think about the problem in a different way.

## Discovery
    1. Notice binary is heavily obfuscated
    2. Examine functions, infer/guess likely behavior/problem paradigm
    3. Develop runtime instrumentation to find flag


## Solution
Use the script below in gdb to generate a file with strings.[2](#endnote2)  This can be done either with "source gdb_script.py" from within the gdb prompt, or from the command line with "gdb -x gdb_script.py ./movfu"

----

# Proof of Exploit/Solution

```python
import gdb
from string import printable as ascii

# modified from: http://0vercl0k.tuxfamily.org/bl0g/?p=226
def get_string_at(addr):
    """
    Is address is a pointer on a string ?
    Only strings with >= 3 characters are allowed
    """
    # we try to see if addr is a pointer on an ASCII string
    p_char = gdb.lookup_type('char').pointer()
    s = gdb.Value(addr).cast(p_char)
    try:
        s = s.string()
    except:
        return None
    if len(s) > 3:
        # we consider it as a true string if it has at last 3 characters
        # but we will display only the first 50 chars
        # but first do an ascii check
        # this is a very lenient one
        '''
        if s[0] not in ascii or \
           s[1] not in ascii or \
           s[2] not in ascii :
            return None
        '''
        # this is a very strict one
        for c in s:
            if c not in ascii:
                return None
        return (s[:50] + '[...]' if len(s) > 50 else s)
    return None

def check_string_reg(regname, f):
    myval = gdb.parse_and_eval(regname)
    #print(type(myval), myval)
    #print("Value:", myval)
    if myval > 0x40000:
        retval = get_string_at(myval)
        if retval is not None:
            retval = str(retval)
            eip = gdb.parse_and_eval("$eip")
            f.write("%s: %s -> %s\n" % (eip, regname, str(retval)))

# Main code starts here
# Registers of interest
regs = [
    '$eax',
    '$ebx',
    '$ecx',
    '$edx',
    '$esi',
    '$edi',
]
# you can define this command in gdb to suppress output on stepping and speed things up a little
"""
define_stepix = '''
define stepix
    set logging redirect on
    set logging file /tmp/whatever
    set logging on
    si
    set logging off
end'''
"""
print("[*] Starting analysis...")
# this suppresses the per-step output for "si", it's an alternative to s/si/stepix/
gdb.execute('set logging redirect on')
gdb.execute('set logging file /dev/null')
gdb.execute('set logging on')
# comment the three lines above if you want to see the execution flow

gdb.execute("break main")  # start stepping at the beginning
gdb.execute("set pagination off")  # let output scroll
gdb.execute("r")
# every instruction, if the register points to a string, dump it
f = open("strings_pointed_to.txt", "a")
while True:
    gdb.execute("si")
    #gdb.execute("stepix")
    for regname in regs:
        check_string_reg(regname, f)
f.close()
# Turning logging back on from within this script doesn't seem to work
```

----

# Endnotes

<a name="endnote1">[1]</a>: [movfuscator github](https://github.com/xoreaxeaxeax/movfuscator)

<a name="endnote2">[2]</a>: gdb has python bindings which are very poorly documented, example [here](http://0vercl0k.tuxfamily.org/bl0g/?p=226)

