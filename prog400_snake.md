# Challenge Name

Pellet Eater

# Point Value and Assessed Difficulty

400

# Category

Programming

# Challenge Prompt/Question

Wakka wakka wakka wakka.gameofpwn.es:5555

# Hints

* __Hint 1:__ *(Heuristics)* If you can come up with smart heuristics, you can probably scrape by.

# Key

SnakesAreLikeNoLeggedNinjas

# Walkthrough

This challenge is similar to many classic computer science solutions.

The basic idea is that we need to find a path that crosses into each square without going into any square twice.

The two ideas that probably come to mind first are breadth-first-search (BFS) and depth-first-search (DFS).  I decided to try DFS, though BFS solution may work for you.[1](#endnote1) 

I wrote my solution in python, which can be provided, but the idea is that a "naive" BFS or DFS solution is unlikely to find a solution in a reasonable amount of time given the search space.  Using a more sophisticated algorithm may yield a more elegant solution, but the idea was to challenge competitors to improve their solution quickly until it was good enough.

The way I implemented a DFS solution was to recursively evaluate squares, starting with the beginning square.

For each square, I test the neighboring squares (up, down, left, right) to see if they were valid moves, in this case if they were the '.' symbol.  For each valid move, I recursively evaluate it to see if it leads to a valid solution.  The DFS comes in because I recur on the first valid move and the paths that come out of it until it comes up as a valid solution or a dead-end.

This is the "naive" solution because it will evaluate every valid path it comes across, even if it's obviously not going to work out.  An example of something that can be easily observed as an invalid path is when a move creates a pocket of unreachable squares that need to be traversed but are now inaccessible.

The first heuristic I created was to solve this problem, by using a reachability test.  For a given move, I use a BFS approach to enumerate all of the reachable squares (yes, DFS would also work).  I count the number of reachable squares, and if it is less than the number of squares remaining (calculated at the beginning and decremented after each move), then the move has created a pocket of unreachable squares, and we should stop evaluating there.

A second heuristic I tried was to keep track of board states and if the board state has already been encountered, to stop evaluating there.  Given that I use a DFS approach, if it's previously been encountered, I know it's not a valid solution, otherwise I'd already have stopped.  This particular heuristic turned out not to be very helpful, but is a good example of a heuristic that's easy to implement (in python anyway).

The third heuristic I implemented when I noticed my solver kept getting stuck making poor move choices early on that would end up making the rest of the DFS search space after that point lack any valid solutions.  The trend I noticed in these cases was that oftentimes there was a move that had more available moves and one that only had one.  These tended to be "tunnels" or areas that needed to be explored first, because if not the path would not be able to fit to them at the end.  I've included an example below.  The heuristic is to take moves that only have one valid next move first, and it proved to work pretty well in practice.

```
................
.##############.
.##############.
.##############.
.##############.
.##############.
.##############.
.##############.
.##############.
.##S............
................
..##............
................
................
```

Starting a path with (down, right) leads to an unsolvable board, but it is not immediately obvious why.  There may be a different test to determine such conditions, but the one I've described got the job done.

There are many different ways to approach the problem, but the simple DFS solution with two heuristics gave a solution that could solve the problem within the time limits, and so it was good enough.  If you took a different approach or used different heuristics, we'd be interested to hear about it.

## Concept Development

This problem is a play on the classic maze-type of programming challenges.  Solving it requires an understanding of basic algorithms and adapting them for solving specific problems.

## Discovery

See walkthrough.

## Solution

See walkthrough

----

# Proof of Exploit/Solution

```python
import sys
from sys import stdout
import copy
from socket import *
import time

HOST = "127.0.0.1"
PORT = 5555

# Example of manual puzzle specification
global_x, global_y = (28, 21)
input_board_str = """############################
#......###..##..###........#
#.####.###..##..###.######.#
#.####.....................#
#.##########..######.#######
#......##............#######
######.##............#######
######.#####..######.#######
#......###........##.......#
#......###........##.......#
######.###........##.#######
######.#############.#######
#......##............##....#
#.......#..........####....#
#..####.#..#######..###..###
#..#.........S...........###
####.###.#########...###.###
#....###....###......###...#
#.#########.###....#######.#
#...........######.........#
############################
"""
# Turn LOCAL_ONLY to True and use the above format to specify mazes yourself
LOCAL_ONLY = False


def all_reachable(board, x, y, moves_left):
    next_move_queue = {}
    move_queue = {}
    b = copy.deepcopy(board)
    move_queue[(x, y)] = 1
    squares_marked = -1  # -1 to account for initial square
    moves_queued = 1
    while moves_queued > 0:
        moves_queued = 0
        for coordinates in move_queue:
            x, y = coordinates
            if b[x][y] == '#':
                b[x][y] = "X"
                print "[!] Unexpected pre-marked square: %d, %d" % (x, y)
                print get_printable_board(b, len(b), len(b[0]))
            squares_marked += 1
            debug = False
            if debug:
                b[x][y] = '*'
                print squares_marked
                print get_printable_board(b, len(b), len(b[0]))
            b[x][y] = '#'
            moves = get_valid_moves(x, y, b)
            for move in moves:
                next_move = make_move(move, x, y)
                if next_move not in next_move_queue:
                    moves_queued += 1
                    next_move_queue[next_move] = 1
        move_queue = next_move_queue
        next_move_queue = {}
    if squares_marked < moves_left:
        return False
    else:
        return True


def read_board_from_string():
    print ""
    x = global_x
    y = global_y
    print "[*] Got dimensions %d, %d" % (x, y)
    board_str = input_board_str
    lines = board_str.split()
    new_board = [['.' for i in range(y)] for j in range(x)]
    for i in range(y):
        line = lines[i].strip()
        print "%d %s" % ((y - 1 - i) % 10, line)
        for n in range(len(line)):
            new_board[n][y - 1 - i] = line[n]
    x_key = "  "
    for i in range(x):
        x_key += "%d" % (i % 10)
    print x_key
    return new_board


def read_until(s, c="\n"):
    buf = ''
    while c not in buf:
        buf += s.recv(1)
    return buf


def read_board(s):
    print ""
    x = read_until(s, ' ')
    y = read_until(s, '\n').strip()
    x, y = int(x), int(y)
    print "[*] Got dimensions %d, %d" % (x, y)
    new_board = [['.' for i in range(y)] for j in range(x)]
    for i in range(y):
        line = read_until(s).strip()
        print "%d %s" % ((y-1 - i) % 10, line)
        for n in range(len(line)):
            new_board[n][y-1 - i] = line[n]
    x_key = "  "
    for i in range(x):
        x_key += "%d" % (i % 10)
    print x_key
    return new_board


def find_start(board, w, h):
    for i in range(w):
        for j in range(h):
            if board[i][j] == 'S':
                return i, j


def valid_move(x, y, board):
    x_max = len(board)
    y_max = len(board[0])
    if x < 0 or x >= x_max or \
       y < 0 or y >= y_max:
        return False
    if board[x][y] != '.':
        return False
    return True


def get_valid_moves(x, y, board):
    moves = []
    if valid_move(x, y+1, board):
        moves.append('up')
    if valid_move(x, y-1, board):
        moves.append('down')
    if valid_move(x+1, y, board):
        moves.append('right')
    if valid_move(x-1, y, board):
        moves.append('left')
    return moves


def make_move(move, x, y):
    if move == 'up':
        return x, y+1
    if move == 'down':
        return x, y-1
    if move == 'left':
        return x-1, y
    if move == 'right':
        return x+1, y


def get_moves_left(b):
    moves = 0
    for i in range(len(b)):
        for j in range(len(b[0])):
            if b[i][j] == '.':
                moves += 1
    return moves


def print_board(board, x_max, y_max):
    for y in range(y_max-1, -1, -1):
        for x in range(x_max):
            stdout.write(board[x][y])
        stdout.write("\n")
    print ""


def get_printable_board(board, x_max, y_max):
    b = ''
    for y in range(y_max-1, -1, -1):
        for x in range(x_max):
            b += board[x][y]
        b += "\n"
    return b

move_chars = {
    'up': 'u',
    'down': 'd',
    'left': 'l',
    'right': 'r',
    'start': 'S',
}
boards = []
frames = 0


def recursive_solve(b, w, h, x, y, left, path, last_move='start'):
    global frames
    if left == 0:
        return path
    # It's key to save before overwrite of N, otherwise you can confuse a losing path with a half-finished success
    if b in boards:
        return None
    if not all_reachable(b, x, y, left):
        return None
    if len(boards) > 10000:  # shouldn't need this
        boards.pop(0)
    boards.append(b)
    b[x][y] = "C"
    valid_moves = get_valid_moves(x, y, b)
    ordered_valid_moves = []
    # Heuristic to tend towards last move
    if last_move in valid_moves:
        valid_moves.remove(last_move)
        valid_moves.insert(0, last_move)
    # Heuristic to pick smart moves first
    for move in valid_moves:
        next_x, next_y = make_move(move, x, y)
        next_valid_moves = get_valid_moves(next_x, next_y, b)
        num_next_moves = len(next_valid_moves)
        # Pick moves that only have one way out first
        if num_next_moves == 1:
            ordered_valid_moves.insert(0, move)
        else:
            ordered_valid_moves.append(move)
    for move in ordered_valid_moves:
        move_char = move_chars[move]
        new_path = path + move_char
        new_board = copy.deepcopy(b)
        next_x, next_y = make_move(move, x, y)
        frames += 1
        new_board[x][y] = "L"
        new_board[next_x][next_y] = "N"
        debug = False
        if debug:
            print left
            print_board(new_board, w, h)
        if (frames % 1000) == 0:
            print "%d states examined" % frames
            print_board(new_board, w, h)
        new_board[x][y] = move_char
        new_path = recursive_solve(new_board, w, h, next_x, next_y, left-1, new_path, move)
        if new_path is not None:
            return new_path
    # if we're here, we exhausted available moves without a solution
    return None


def solve(b, w, h, x, y):
    global frames
    moves_left = get_moves_left(b)
    print "%d moves left" % moves_left
    frames = 0
    start = time.time()
    path = recursive_solve(b, w, h, x, y, moves_left, path='')
    duration = time.time() - start
    print "Path: %s" % str(path)
    print "Found in %d frames.  Took %d minutes, %d seconds" % (frames, duration//60, duration % 60)
    return path


def main():
    start_time = time.time()
    if LOCAL_ONLY:
        board = read_board_from_string()
        w = len(board)
        h = len(board[0])
        print "Dimensions: %d by %d" % (w, h)
        start_x, start_y = find_start(board, w, h)
        print start_x, start_y
        # print board
        path = solve(board, w, h, start_x, start_y)
        print "[+] Path: %s" % path
    else:
        s = socket()
        print "[*] Connecting to %s:%d" % (HOST, PORT)
        s.connect((HOST, PORT))
        print "[+] Connected"
        msg = read_until(s, "Ready?\n")
        print msg
        while True:
            board = read_board(s)
            w = len(board)
            h = len(board[0])
            print "Dimensions: %d by %d" % (w, h)
            start_x, start_y = find_start(board, w, h)
            path = solve(board, w, h, start_x, start_y)
            s.send(path + "\n")
            print "Sent path"
            print read_until(s, "\n")
    end_time = time.time()
    duration = end_time - start_time
    print "[*] Finished in %d minutes, %d seconds" % (duration//60, duration % 60)

if __name__ == "__main__":
    main()
```

----

# Endnotes

<a name="endnote1">[1]</a>: Wikipedia has a fair discussion of DFS [here](https://en.wikipedia.org/wiki/Depth-first_search)
