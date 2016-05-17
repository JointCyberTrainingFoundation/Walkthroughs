<!-- name this file 2016_JCC_CategoryName_ChallengeName.md -->

# Challenge Name
Cosmo Crew

# Point Value and Assessed Difficulty
250

# Category
Programming 

# Challenge Prompt/Question
You are on a cosmo crew!  space.gameofpwn.es:45429

# Hints
* __Hint 1:__ *(Similar Game)* This challenge is modeled after the excellent mobile game Spaceteam.  If you're confused about how it's supposed to work, you might give it a try.
* __Hint 2:__ *(Juggling input/output)* You'll have to play multiple players and pass data between them, but mult-threading isn't required.  Select() is enough.

# Key
Sp@ceB11111ts...CrunchingAllTheSpaaaceBiiits!

# Walkthrough
Challengers will need to be able to connect to multiple sockets and pass input and output between them, as well as manage state.

They will have to connect to the sockets, parse out the verbs and nouns from one, and pass the command to the appropriate socket.  This can be done either with threading or select().

## Concept Development
This challenge came from the idea of how difficult and fun the game Spaceteam is to play as a team, and how it could be translated to text interface.  It shows how some games are extremely simple to automate solutions for.

## Discovery
    1. Connect to the server, read the instructions
    2. Connect to the player ports with netcat or scripting, and understand the formatting of the game
    3. Write a program to play the game and get the flag

## Solution
Keep global state, use select to poll through the client sockets.  Parse out the devices each player is responsible for, and then read from one player the commands and have the device owner enter the command.  The concept isn't as difficult as executing correctly under a time constraint.

----

# Proof of Exploit/Solution

```python
from socket import *
import select
import time

DEVICES_PER_PLAYER = 5
HOST = "127.0.0.1"
PORT = 0xb175
NUM_PLAYERS = 8
DEFAULT_LEN = 1000

def peek(s):
    readable, writable, error = select.select([s,], [], [], 0.1)
    if readable:
        return True
    else:
        return False

def recv_until(s, max_len=DEFAULT_LEN, terminator=None):
    data = ""
    start = time.time()
    TIMEOUT = 5
    while True:
        if time.time() - start > TIMEOUT:
            print "[!] Timeout reached in select loop"
            return data
        readable, writable, error = select.select([s,], [], [], 0.5)
        if readable:
            c = s.recv(1)
            data += c
            if (terminator and data.endswith(terminator)) or len(data) > max_len:
                break
        else:
            break
    return data

def recv_line(s, max_len=DEFAULT_LEN):
    return recv_until(s, max_len, "\n")

def recv_and_print(s, bufsize=DEFAULT_LEN, terminator=None):
    data = recv_until(s, max_len=bufsize, terminator=terminator)
    print "Received %d bytes: ```%s```" % (len(data), data)
    return data

def parse_lines(d):
    lines = d.split("\n")
    players = [0] * NUM_PLAYERS
    for line in lines:
        if line.startswith("Player "):
            words = line.split(" ")
            port = int(words[-1])
            player = int(words[1].replace(",", ""))
            players[player] = port
    for i in range(len(players)):
        print "Player %d : port %d" % (i, players[i])
    return players

def connect_all(ports):
    player_sockets = [0] * NUM_PLAYERS
    for player, port in enumerate(ports):
        s = socket()
        s.connect((HOST, port))
        if player == 7:
            terminator = "bunch\n"
        else:
            terminator = "connect\n"
        recv_and_print(s, terminator=terminator)
        player_sockets[player] = s
    return player_sockets

def all_skip_n_lines(player_sockets, n):
    for i, s in enumerate(player_sockets):
        print "[DEBUG] %d" % i
        for j in range(n):
            recv_and_print(s, terminator="\n")

def all_recv_until(player_sockets, terminator):
    for i, s in enumerate(player_sockets):
        print "[DEBUG] Player %d" % i
        d = recv_and_print(s, terminator=terminator)
        if "Congratulations" in d:
            print "[+] Looks like we won, let me pull the flag out of the socket here, justaminnit..."
            flag = recv_until(original_socket)
            print "Flag: ```%s```" % flag
            print "Winning."
            exit(0)

def read_all_devices(player_sockets):
    devices = [[]] * NUM_PLAYERS
    device = ""
    for i, s in enumerate(player_sockets):
        devices[i] = []
        while True:
            device = recv_until(s, terminator="\n").strip()
            if device.startswith("---"):
                break
            devices[i].append(device)
    for i, device in enumerate(devices):
        print "[*]", i, device
    return devices

def get_commands(player_sockets):
    commands = [""] * NUM_PLAYERS
    for i, s in enumerate(player_sockets):
        commands[i] = recv_until(s, terminator="\n")
    for i, command in enumerate(commands):
        print "Command for player", i, command.strip()
    return commands

def respond_to_command(player_sockets, devices, commands, command_owner):
    command = commands[command_owner]
    print "[*] Command owner: %d, command: %s" % (command_owner, command.strip())
    verb, noun = command.split("the ")
    verb, noun = verb.strip(), noun.strip()
    # find device owner
    device_owner = 999
    done = False
    for me, my_devices in enumerate(devices):
        for device in my_devices:
            if device == noun:
                device_owner = me
                done = True
                print "[*] Device owner %d, devices: %s" % (me, devices[me])
                break
        if done:
            break
    # device owner, do action
    device_owner_sock = player_sockets[device_owner]
    action = "%s the %s\n" % (verb, noun)
    print "[*] %d sending %s" % (device_owner, action.strip())
    device_owner_sock.send(action)
    ack = recv_line(device_owner_sock)
    print "[*] Acknowledgement:", ack.strip()
    if not ack.startswith("FWOOSH"):
        return commands
    # command owner, get new action
    new_command = recv_line(player_sockets[command_owner])
    if new_command == "\n":
        print "Did we win?"
        return None
    if len(new_command) < 4:
        print "Something went wrong..."
    print "[*] New command:", new_command
    commands[command_owner] = new_command
    return commands

#############################################
original_socket = socket()
original_socket.connect((HOST, PORT))
d = recv_and_print(original_socket, 3000)
player_ports = parse_lines(d)
player_sockets = connect_all(player_ports)

#Play stage
while True:
    # recv_all info for this stage -- devices
    #all_skip_n_lines(player_sockets, 5)
    all_recv_until(player_sockets, "Your devices:\n")
    devices = read_all_devices(player_sockets)
    # ignore 3,2,1
    time.sleep(0.5)
    print "[*] Sleeping 3,",
    time.sleep(1)
    print "2,",
    time.sleep(1)
    print "1,",
    time.sleep(1)
    print "go."
    time.sleep(0.5)
    all_skip_n_lines(player_sockets, 4)

    # respond to commands in round-robin fashion
    commands = get_commands(player_sockets)
    cur_player = 0
    while True:
        commands = respond_to_command(player_sockets, devices, commands, cur_player)
        if commands is None:
            break
        cur_player = (cur_player + 1) % NUM_PLAYERS
    # re-sync (winning player will likely be one line ahead)

print "[*] Done"
```

----

# Endnotes

