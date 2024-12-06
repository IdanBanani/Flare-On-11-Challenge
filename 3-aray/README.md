# Challange 2 - aray (yara in reversed form)

Difficulity level - **quite easy, but tricky. requires some thought**   
don't invest too much time on writing a "good looking" solver

## First step - Clean up the code
- Using regex like Find and replace (code editor / sed / cyberchef) see [Washi writeup](https://washi1337.github.io/ctf-writeups/writeups/flare-on/2024/3/)
- `$ tail -n 2 aray.yara | head -n 1 | sed 's/and /\n/g' | sort` 
- `$ cat aray.yara | grep filesize | sed 's/ and /\n/g'`
- [some more vscode tricks](https://github.com/DisplayGFX/DisplayGFX-CTF-writeups/blob/main/flare-on/flare11_chall3.md#solving-the-yara-rule-with-vscode)
- using python package `plyara` to extract just the rule
## Understanding the logic of the given yara rules


## Should you bother removing the inequality "!=",greater/lower than conditions?
[The official writeup](https://services.google.com/fh/files/misc/flare-on11-challenge3-aray.pdf) mentions that these and some other conditions are basically **either not helpful or always true** (like for flag_byte & 128 == 0).
noticing that requires some thinking effort.

So we can remove these conditions like `!= , > , <` and see if we reach a single solution
These can be done using regular expressions do delete such lines
**leaving them for Z3 solver to handle will also work** but might make things slower.

Again, **Taking into account only the == conditions reduces by far a lot the number of constraints!** [so much that some people decided to solve manually!](https://github.com/gray-panda/grayrepo/blob/master/2024_flareon/03_aray/soln.py)) It's a good aproach to start from there and see we reach a solutiokn

## Z3 vs solving byte by byte without Z3
- Writing a "reverse" solver function for each of the yara operations (uint8,uint32,xor,or, etc.) is possible and will work, 
this will work and the only benefit of it is not having to deal with Z3 syntax, And in general- no need to modify the conditions, but:
    - This requires **parsing line by line** and calling the relevant **parser "solver" function for each condition**
    - The other way is **going crazy with cryptic regular expressions like in the** [official writeup](https://services.google.com/fh/files/misc/flare-on11-challenge3-aray.pdf) or [ispoleet code](https://github.com/ispoleet/flare-on-challenges/blob/master/flare-on-2024/03_aray/aray_crack.py) it works, **but it's not so human readable**.
    - note: **Python 3.10** added support for **match case statement syntax**
    - **You can make it compact and short putting in some extra time and effort (complex logic/ regex/ functional programming)** [see 0xdf writeup](https://0xdf.gitlab.io/flare-on-2024/aray) - Though I'm not sure this is the way to go...
- Solving with C/CPP syntax [Hasherezade solver](https://github.com/hasherezade/flareon2024/blob/main/task3/sol.cpp)- **Why would you do that? X_X**

- Using Z3
  - Will require adding new constraints using the solutions for the hashes cracking (since we are feeding z3 the whole vector/flag content), and ofcourse - not feeding it with the original hash conditions. ([example solver](https://paste.ofcode.org/brD7b7TNE6C8kCNrJxmhTb))
  - Will require applying text replacement for multiple lines at once for adaptaion (like find and replace using regex,or selecting multiple lines with cursor)
  - **Will enable us to elminate the need for implementing specific conditions solvers**
    - **Except for using other code for bruteforcing bytes by hashes**
  - You can either simplfy and change some of the conditions like [Washi did](https://washi1337.github.io/ctf-writeups/writeups/flare-on/2024/3/)
    - **Or perhaps even better** use the relevant Z3 function to handle it like z3.ULT , z3.UGT (see [SuperFashi writeup](https://gmo-cybersecurity.com/blog/flare-on-11-write-up/) - **probably the most elegant solver**, **uint32() and uint8() acts the same in Z3**)  instead of translating uint32 using "bit twiddling hacks" which is not hard to write: `s.add((data[41] | (data[41+1] << 8) | (data[41+2] << 16) | (data[41+3] << 24)) + 404880684 == 1699114335)` -

# gotchas
- endianess for **uint32**: trial and error or let z3 handle it for you
- yara rules/conditions syntax (hashes,offsets): simply google it...
- in case you parse conditions from a file
  - Be careful when removing multiple lines at once from the conditions text (using code editor etc.) due to line feeds / CRLF etc.
  your solver script () may fail for weird reason 