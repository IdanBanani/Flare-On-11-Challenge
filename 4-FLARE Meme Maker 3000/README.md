Difficulity: easy
Not so interesting challenge unless you try to manually deobfucate the code

# Trying to format the code first
- Firefox developer tools -> format code
  
Then we notice it requires deobfuscation...

# Deobfuscating the js code
code was obfuscated with <https://github.com/javascript-obfuscator/javascript-obfuscator>
- although possible to do so manually, it will require more time and effort, but may be somewhat more educational
  -  see [washi writeup](https://washi1337.github.io/ctf-writeups/writeups/flare-on/2024/4/)
  -  see also [stong/cts writeup](https://github.com/stong/flare-on-2024-writeups/tree/master/4-mememaker)
- Automatic deobfuscation - not all deobfuscators are made equal!
  - <https://deobfuscate.relative.im/> (implemented with typescript <https://github.com/relative/synchrony>)
  - Flare VM has it built in one taken from [another project (the official writeup has a mistake, stating that it's the same project)](https://github.com/ben-sb/obfuscator-io-deobfuscator))
    - `obfuscator-io-deobfuscator obfuscated.js -o deobfuscated.js`
  - Webcrack <https://github.com/j4k0xb/webcrack>
    - see [video 0xdf](https://www.youtube.com/watch?v=imiuHXlq37g)

# Strategies
SuperFashi:
    Since a0k is the only large function with cryptic looking code in it, it should be the function related to flag, 
    especially the final atob('Q29uZ3JhdHVsYXRpb25zISBIZXJlIHlvdSBnbzog') executes to the string Congratulations! Here you go:.
    Therefore, the variable f must be the flag string under right conditions.

- you can also start from the eventlistener and keyup logic
##  For reverse engineering/debugging purposes
you can either copy the debofuscated code and paste instead of the obfuscated js code into the html or open the html in browser pasting the js code inside the developer options console

## Reverse engineer the relevant code logic
- Find the correct set of values of meme, text,labels etc. that will match the conditions in the script for showing the flag
    - **naive approach**: clicking the buttons untill the right combination of 3 (random?) text labels appears
    - **smarter approach**: we can set the values to the needed ones at runtime (debugging/ patching the source code on front end side). see:
      - [example](https://0xdf.gitlab.io/flare-on-2024/meme-maker-3000)
      - [superFashi](https://gmo-cybersecurity.com/blog/flare-on-11-write-up/)
      - Manually deobfuscating and setting the right values, possible but not needed. it is convenient since we have only 3 labels vars.
  ![](https://github.com/ispoleet/flare-on-challenges/raw/master/flare-on-2024/04_mememaker3000/images/flag.png)