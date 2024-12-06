# Challange 2 - Checksum

Difficulity level - **easy, but requires some experience with static analysis, debugging, patching etc.**  

Somewhat painful to reverse even the decompiled code since it's written in Go (use ghidra / IDA Pro 9). So knowing x86 assembly is very helpful.

We are given a windows .exe PE binary (CLI, no GUI)

## Some very nice static analysis/writeups  

[official writeup](https://services.google.com/fh/files/misc/flare-on11-challenge2-checksum.pdf) - Extensive with a deep dive into the decompiled code (Only a single image of dissassembly!!!, which is for the decryption stage)  
[Washi writeup](https://washi1337.github.io/ctf-writeups/writeups/flare-on/2024/2/)
[0xdf writeup](https://0xdf.gitlab.io/flare-on-2024/checksum )  
[gf_256/cts writeup](https://github.com/stong/flare-on-2024-writeups/tree/master/2-checksum)  

## SuperFashi note

        However, although Ghidra (and IDA) claims to have good Golang support, in real situations like this one, 
        I found that the decompiled code is still a bit hard to read. 
        The strings are not processed good enough, and function call arguments and return values are all over the place because of the non-conventional calling convention. 
        When in doubt, remember to always consult the disassembler.

## Finding strings inside the binary (like the base64 encoded string)

**Problem**: Not only it has tons of strings, but even if we try to look for very long strings we will get noise
see [0xdf note](https://0xdf.gitlab.io/flare-on-2024/checksum#strings) ,"That’s because of how Go stores strings, not null terminated, but all jammed together and referenced by offsets and lengths."
**TODO**: try a more sophisticated tool like the one from Mandiant [Flare-Floss](https://github.com/mandiant/flare-floss)

## Validation checks on user input for sum of two random numbers in a random interation count loop

**since it doesn't affect the flag content** It might be a good idea to bypass it with patching the binary at the assembly level, instead of manually/automatically answering the challenges (which is quite easy, see [gray-panda writeup](https://github.com/gray-panda/grayrepo/tree/master/2024_flareon/02_checksum)).  

### examples for patching

- [cano32](https://cano32.github.io/writeups/FlareOn11-2024#2)
- [Jinmo123 video](https://youtu.be/WLSZPC5ZagY?t=670) `jge->nop + jmp`  
  
note that you can also patch at while debugging with `x64dbg` etc.

## Methods to find code of interest

- Looking for interesting functions names, in this we have 3 named under `main_?` package/class, and `chacha20poly1305` functions
- While debugging - Trying to advance each time in the codeflow runtime logic (bypassing redundant checks), supplying input and with trial and error and afterwards search for the output text inside IDA/Ghidra
- Looking for string/memory comparision function calls/syscalls (in our case `runtime_memequal()`)
  
## Once the juicy logic is found

(decoding the hardcoded base64 string and xoring it with `b"FlareOn2024"` to get the decryption key and supply it to the program), solving the challenge gets easy and quick (see [solver code](https://github.com/tosbaha/reverse/blob/main/ctf/flareon%202024/02/solution.py)), we just supply the binary the sha256 string.  
example: [cyberchef recipe](https://cyberchef.org/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)XOR(%7B'option':'UTF8','string':'FlareOn2024'%7D,'Standard',false)&input=Y1FvRlJRRXJYMVlBVncxelZRZEZVU3hmQVFOUkJYVU5BeEJTZTE1UUNWUlZKMXBRRXdkL1dGQlVBbEVsQ0ZCRlVubGFCMVVMQnlSZEJFRmRmVnRXVkE9PQ). you can also use pwntools: `from pwn import xor`  
or use your own **python** snippet:

```python
import itertools

def cyclic_xor(data: bytes, key: bytes) -> bytes:
    return bytes(d ^ k for d, k in zip(data, itertools.cycle(key)))
```

So there's no even a need to reverse the encryption algorithm used or noting the usage of `main_encryptedFlagData` for the decription stage (resulting in an image with the flag).  
The requested **sha256** hexdigest string is actually the one of the flag image and it's being used as a decryption key

## Gotcha's

### reverse engineering the expected decryption key

Since judging by "obfuscated" decompiled code, it might not be so obvious that the bytes of the (**xor key**) `b'FlareOn2024'` are xored with the user's sha256 bytes **in a cyclical/python-zipped liked fashion**, one might take the decompilation output as is for finding the calculated index inside the `b'FlareOn2024'`  (hint: the constant 11 in the formula which is the length of the xor-key string, for modulo operation)
You can basically "assume" it does that and then verify the solution instead of going for [An overkill solution that ignores this assumption, although it's true that you should always verify your assumptions were true](https://vaktibabat.github.io/posts/flareon2024/#how-is-the-checksum-verified)

### Finding out what is the fullpath of `os::os.UserCacheDir()\REAL_FLAREON_FLAG.jpg` at runtime

translates to `%LocalAppData%`\.... which can be accessed with file explorer or inspecting the value of this environment var in powershell etc.

- Debugging with breakpoints (string pointed by register rax etc.), requires identifying the right spot to put a breakpoint - **Quite easy and fast**
- [Official documentation](https://pkg.go.dev/os#UserCacheDir) is **quite useless**  
- Google/chatgpt the usual returned values - "cheating"
- **A very nice method** : using process monitors/tracers like `procmon` to identify `WriteFile` operations ([see official writeup](https://services.google.com/fh/files/misc/flare-on11-challenge2-checksum.pdf))  
- Use whole system search like with `void-tools Everything` for the file name `REAL_FLAREON_FLAG.JPG`
- **Also nice method**
  - while debugging - dump the to be written image bytes into a file on hard disk
    - IDA/Ghidra/x64dbg/windbg etc. ,  copy to clipboard/ save to file the raw bytes
      - echo -ne '\xFF\xD8\xFF...' > output_image.jpeg
      - paste raw bytes in hex editor like 010/HxD  etc.
- **As a last resort** maybe patching the binary, hooking specific function calls or editing memory/registers content while debugging, such that it will be written to a known path.

## Appendix

Introduction to chacha20-poly1305. **Not needed for the solution**  
<https://dev.to/jaypmedia/cipher-suites-aead-chacha20-poly1305-example-1i6>

Golang specific documentation  
<https://pkg.go.dev/golang.org/x/crypto@v0.27.0/chacha20poly1305#pkg-overview>
