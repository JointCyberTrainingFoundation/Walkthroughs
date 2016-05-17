# Challenge Name
Chef Boyardee

# Point Value and Assessed Difficulty
75

# Category
Programming

# Challenge Prompt/Question
Word is that the zamboni whisperer picked his favorite word and a substitution cipher to protect his communications.

Connect to salad.gameofpwn.es:49662, and read his communiques using the word zamboni as the password.

# Hints

* __Hint 1:__ *(Subsitution Cipher Password)* Wikipedia has an article on substitution ciphers showing how they incorporate a password.
* __Hint 2:__ *(Layering ciphers) You need to use both layers in the right order to communicate to and from the server.

# Key
IFONLYCAESARKNEWABOUTELLIPTICCURVE

# Walkthrough
This is a simple substitution cipher problem, it just requires the knowledge from wikipedia and basic socket programming. [1](#endnote1)

The only trip is the switch from one layer to two layers of ciphers, and the ability to send in the double-layered cipher, the solution python file shows a straightforward way to do this.


## Concept Development

This is a basic programming challenge that gets challengers thinking about socket programming and handling strings and doing character manipulation.

This is the sort of thing any programmer should be able to do in a language they are or want to be familiar with.

## Discovery


## Solution

----

# Proof of Exploit/Solution

```python
import string
from collections import OrderedDict
from socket import *
import time
import select

HOST = "127.0.0.1"
PORT = 0xc1fe

def fix_string(s):
    return s.replace(' ','').upper()

def get_new_alphabet(word):
    unique_letters = OrderedDict.fromkeys(word + string.ascii_uppercase).keys()
    new_alphabet = "".join(unique_letters)
    return new_alphabet
    
def do_substitution(message, substitution, alphabet=string.ascii_uppercase):
    translation_table = string.maketrans(alphabet, substitution)
    return message.translate(translation_table)

def cipher(message, word):
    message = fix_string(message)
    word = fix_string(word)
    alphabet = get_new_alphabet(word)
    return do_substitution(message, alphabet)

def decipher(message, word):
    message = fix_string(message)
    word = fix_string(word)
    alphabet = get_new_alphabet(word)
    return do_substitution(message, string.ascii_uppercase, alphabet)

s = socket()
s.connect((HOST, PORT))
op = "zamboni"
prompt = s.recv(200).strip()
print "[*] First received", prompt
d_once_prompt = decipher(prompt, op)
print "[*] Deciphered:", d_once_prompt
ip = "calvinesque"
d_twice_prompt = decipher(d_once_prompt.split("XXX")[1], ip)
print "[*] Double deciphered:", d_twice_prompt
#answer = "Chef Boyardee"
answer = "George Washington"
d_once_answer = cipher(answer, ip)
d_twice_answer = cipher(d_once_answer, op)
print "[*] Sending %s" % d_twice_answer
s.send(d_twice_answer + "\n")
response = s.recv(200).strip()
print "[*] Response:", response
d_once_response = decipher(response, op)
d_twice_response = decipher(d_once_response, ip)
print "[*] Double-deciphered response:", d_twice_response

```

----

# Endnotes

<a name="endnote1">[1]</a>: Wikipedia has a lot of good information on simple ciphers like substitution ciphers [here](https://en.wikipedia.org/wiki/Substitution_cipher)
