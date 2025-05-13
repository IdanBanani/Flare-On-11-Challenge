Difficulity: Medium  

**@TODO:** Mention this (crazy) writeup using unicorn : [Written by Pedro Vilaca](https://reverse.put.as/2024/11/29/flare-on-2024-sshd/)  

**Very interesting challenge** with many newances, things going under the hood, and skills you can/need to learn/use to manage to solve it faster/easier.

    Our server in the FLARE Intergalactic HQ has crashed!
     Now criminals are trying to sell me my own data!!!
      Do your part, random internet hacker, 
      to help FLARE out and tell us what data they stole! 
      We used the best forensic preservation technique of
       just copying all the files on the system for you
    
Note that there was some hint about some **crash** and stealing/leakage of data

If you are looking for some introduction on the exercise, take a look at [official writeup](https://services.google.com/fh/files/misc/flare-on11-challenge5-sshd.pdf) and come back.

you can also take a look at [yamsbot writeup](https://yams.bot/writeups/flareon2024/sshd/)

many other good writeups will be mentioned next

# How was the container dump created?

Typically a coredump will be created (Once configured to be enabled) by `systemd` daemon and stored in `/var/lib/systemd/coredump`

Some open source tools for creating docker image from a snapshot like <https://github.com/fox-it/acquire> are available open-source.

# Forensics stage - What files should we inspect?

## Looking at newest touched files

- sort image files by last modified date see [stong/cts writeup](https://github.com/stong/flare-on-2024-writeups/tree/master/5-sshd#5-sshd) for further explanations
- `$ find ./ -type f -exec ls -lt --time-style=+"%Y-%m-%d %T" {} + | sort -k6,7`
  
- `$ locate coredump` (`$ sudo apt install plocate`)
- `$ find . -type f -printf '%T@ %p\n' | sort -nr  | head`

```bash
sudo docker build -t test/ssh_box
sudo docker run -p 127.0.0.1:8080:23946 -p 127.0.0.1:8081:22 --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -it test/ssh_box /bin/bash
```

some more examples: [link](https://hackmd.io/@koala7788/flare-on_11)  

([from Washi's writeup](https://washi1337.github.io/ctf-writeups/writeups/flare-on/2024/5/)):

```shell
sudo docker import ssh_container.tar
```

will give back hash for the container, then we use it like:

```shell
sudo docker run --rm -it sha256:4e1c4961 /bin/bash
```

out of all recently changed files, these are of main interest:

```bash
sshd
liblzma.so.5.4.1
sshd.core.93794.0.0.11.1725917676
```

`/var/lib/systemd/coredump/sshd.core.93794.0.0.11.1725917676`  

## (Statically) Looking for suspicoius files that were patched (to add malicious code/dependencies)

even though you can verify that `sshd` was indeed patched (compared to original for that distro, it was done such that a coredump for it can be created with a process dump), **only the last two files (lib and cored file) are interesting for us**

note that when running `file` command on the coredump, there is a field `execfn: '/usr/sbin/sshd'`, telling you path of the binary which is the dump for

by googling some strings like `liblzma.so.5.4.1` and `RSA_public_decrypt` you will reach articles about the XZ utils backdoor [like this](https://medium.com/@knownsec404team/analysis-of-the-xz-utils-backdoor-code-d2d5316ac43f), which makes understanding what is going on somewhat easier.

`liblzma.so` lib was patched with a tool named [PLThook](https://github.com/kubo/plthook)

You can use patch diffing but it's actually not needed for solving, the string `RSA_public_decrypt` will appear in: The coredump backtrace (registers,stack memory) and in the blog posts about the backdoor
example: [csmantle writeup](https://csmantle.top/ctf/wp/2024/11/09/ctf-writeup-flareon11.html#5---sshd)

You can also go straight to where the crash happend: [see Washi's writeup](https://washi1337.github.io/ctf-writeups/writeups/flare-on/2024/5/#finding-the-relevant-code)

### Using the distro package manager and "debsums -s"

Taken from [DisplayGFX writeup](https://github.com/DisplayGFX/DisplayGFX-CTF-writeups/blob/main/flare-on/flare11_chall5.md#sshd---static-analysis) (may require installing dependecies first):

```bash
root@kali:/# debsums -s
perl: warning: Setting locale failed.
perl: warning: Please check that your locale settings:
        LANGUAGE = "",
        LC_ALL = (unset),
        LANG = "en_US.UTF-8"
    are supported and installed on your system.
perl: warning: Falling back to the standard locale ("C").
debsums: changed file /lib/x86_64-linux-gnu/liblzma.so.5.4.1 (from liblzma5:amd64 package)
debsums: changed file /usr/sbin/sshd (from openssh-server package)
```

# debugging

- **Note - When not loading/importing the docker image as is, you should use chroot!**  

        sudo chroot [path to archive] /bin/bash lets use the program debsums, and run it with chroot to the system archive.
        Make sure to download the debsums....deb file,
        and the needed supporting deb packages, and install with dpkg -i.
- if you just do `gdb -q ./usr/sbin/sshd ./var/lib/systemd/coredump/sshd.core.93794.0.0.11.1725917676` you will get a warnings **"is not at the expected address"**
- navigate to the root folder of the docker image and run `$ sudo chroot .`
- For loading  symbols, you can also do something similar while in gdb (will have to be repeated each session...) unless done in a **.gdbscript file**

        ```bash
        (base) joe@FlareVM:bins$ gdb ./sshd
        ...
        (gdb) set sysroot ../ssh_container/
        (gdb) core ./sshd.core.93794.0.0.11.1725917676
        ```

- `gdb -ex "set sysroot /home/kali/Desktop/ssh_container" usr/sbin/sshd var/lib/systemd/coredump/sshd.core.93794.0.0.11.1725917676`
- see also: [solib-absolute-prefix](https://stackoverflow.com/questions/24896034/solib-absolute-prefix-vs-solib-search-path-in-gdb)
  - [set_solib-search-path](https://visualgdb.com/gdbreference/commands/set_solib-search-path)

`gdb sshd -c /var/lib/systemd/coredump/sshd.core.93794.0.0.11.1725917676`

`/lib/x86_64-linux-gnu/liblzma.so.5`

Use backtrace (`bt`) / `where` command when debugging the coredump

Inside `0x93f0` offset, we see constants such as `0x3320646e61707865` and `0x6b20657479622d32`, which are constants for `ChaCha20 cipher`. Note that `Salsa20`, which `ChaCha20` based on, **uses the same constants**. The identifying part here is that the **nonce** used is **12 bytes, which only exists in ChaCha20**.

Also, with a simple search it is possible to find the exact code used for the functions [C code](https://github.com/spcnvdr/xchacha20).

why did the sshd code crashed? take a look at this code:

```c
    func = "RSA_public_decrypt ";               // space causes a NULL to be returned from dlsym
  }
  RSA_public_decrypt = dlsym(0LL, func);
```

for more information: see [Washi's writeup](https://washi1337.github.io/ctf-writeups/writeups/flare-on/2024/5/#understanding-the-crash)

---------------------

    There are two "distinct"  stages for reaching the flag 
    (though one might write a single script for solving at one shot, especially with emulation)

# Extracting the shellcode for analysis purposes

Once we realize that the backdoor code deciphers and then executes a shellcode (and once done, re-encrypts it), we wish to extract it in its decrypted form for further investigation.

## The "reverse engineering" static way - (Using the encrypted shellcode + chacha20 parameters from coredump)

- [example for code](https://paste.ofcode.org/HkJFm4mu6mS4uT76fLMzNP), taken from [here](https://gmo-cybersecurity.com/blog/flare-on-11-write-up-ja/)
- do it yourself method:
  - First, extract the encrypted shellcode raw data:

    ```c
    (gdb) dump memory shellcode.bin 0x00007f4a18ca9960 0x00007f4a18caa8f6
    ```

  - write code for decryption the shellcode yourself
    - [Example 1](https://github.com/ispoleet/flare-on-challenges/blob/master/flare-on-2024/05_sshd/sshd_decrypt_shellcode.py)
    - [example 2](https://paste.ofcode.org/UYH7SLhZFyDHTzCkYKQSuu)
  - [cyberchef recipe](https://gchq.github.io/CyberChef/#recipe=ChaCha(%7B'option':'Hex','string':'94%203d%20f6%2038%20a8%2018%2013%20e2%20de%2063%2018%20a5%2007%20f9%20a0%20ba%202d%20bb%208a%207b%20a6%2036%2066%20d0%208d%2011%20a6%205e%20c9%2014%20d6%206f'%7D,%7B'option':'Hex','string':'f2%2036%2083%209f%204d%20cd%2071%201a%2052%2086%2029%2055'%7D,0,'20','Hex','Raw')&input=MEZCMDM1NEU4MUZENTBFNTA0QkY2QjFCQzIwRjY2MTY3RjFBODA2NjAxNEIzRkVEQTY4QkFBMkQ0MkFFM0JFODdDRTg3MDMwMzVFNjMyMjIzRDhBQjlERjk3NjlCMzQyNkRFNDg0NjY1QkM3RDUyOTUzNDcwNzNFQ0ZGQjI5QkZDMjFGMzZERDI4NDE0NkEzNjg5OUZGRUZFOUQwQzVFNzFGREE1OEFEQkNCMzkyNEQ5MjNGQzU4MEQ2REZEOEZCQzNDQzNFNDVDMzE5QzBDQUYzODBFNTQ1ODRCM0VDQTc4ODUzRUI5RjdFN0NDOTIxRjE1RDUyNjM5NERFNjVGNTNCMTgxMTdFNEUwMzBBMzExRTU3RDBEMjQ4MzY4QTYwN0NFMTVGRkU3NzRGNDE3RkM3MjZEMzJFQzA5RDI2NjE0NDc5MkFBRUFEQzJEMzkxQkZCQTk4N0FCREVEMUNFMTEyNTM3OUU5QTk3MzgzOUNERkM2MTEwMUQxQTk0NDQyQkQ3NjU5MzJFMDE3RkM1M0RDQThFRUJDOTY3OURDNDcxODVEMTIwQTFBRTU2QjU0RTVDREVFOUI1Njg3RDVCMUU4NkQ4REE5NTdFNkU5ODZBQjRBN0ZBQUQ5MzNERkQwNzc1OUY4RDdDRjQxNTJDNzk4QkQ1MUE3QzJDODM1NTUxMkQ0QjNCNUFCRUYzRTNCNzM4MThFMzAyNzZCODBFMkQxQ0RENzE0RkI0OEQxRTg5NEREQTMwQTZBMkQwNDE3Qzc1MDdCNTU1MkQ2M0JCRTdDRUFEMEE0RjdDMDY5QkU1NzY1Q0M2MUJBNjcxRUZDODAxMTM5MEU4MTQzQjg5QUY1NzM0NjE3QTMxQUREMzI2NTUwQUZEMjNFODNCNTYyMEQ0NDE1RkE5MkI3QzBDQzcwQUZGNkMyRTMzMzBFRkY4QzkwMUNEMTZFQzA4MTlBRTdFNTBFRkE4NkI1NTM1QUNDQjM4MTA5REY3NkQxODMyRkNGRDgwREZGRDczQjQzQzJDMUI3QzdERjA1NzY2Qzg4N0QyOEVDMEZFRkY0OEIxMkNERkMwOERCQkQ4MjAwN0NGMzk1OEU0MUNERkRGREVFMEY2RUEzOTk4Njk3M0JCMzIzNDEzNUY2NjY5MEEyNUFFQUJCRkNCMEY0NERENTQ4MTQ3MTI0OThDMjMzMTE4NkYwRjdBMUY4MTQwQzFDRUFENEFCNDBGNUI3OUEwMDBBNDA3MjQ2NkIyM0IzMEIxNDVERjBBMzVFMkIwRTU1RjZCQkRDMUNFOTlGQTY3NEM1MUMyOTFENTkwNDk2NTFDMjk2OEJENDMxRDUyQ0UwOTVCRjRCRENFODUyNEZCMDc3QkZGREJGN0NCQUUzMjBEMjc1MTdGRUYwMzRFNDNFQkJENzU2RTYyNUU4MEJBNzFDNUJGMkVCMjQ0NTcwNjI5RDc0QkQ4RUU1QzRGRDczMENBMUExMDRCMEU0M0Y0MUMyRDlCQTczRDJEMTZBOEMzN0JDMkJFRTM3RUNFMDFGQTNGMDNBNDBCREU3MENDRDM0RTdGMEI3OTdDQzVCNTI0RjgwRUQ0RjFFNUIwNDdFNjJEN0EwQTMwMDNENURDRDg1MEQwMzVBQzAwRTYzNDQxOUZEQzIyQjQ4M0ZFODFENEVGNjE0RkZBQzc1QTJGNDE4NTUzMjUwM0JENERGMDhDMjdGNUI5Q0QyRDhCQkM0MjMxMUZFOUQwNDk5NDhBRjM2RjFBRkY1NjVFRDMwQjZFNjExMTM2NTlCRjY5Nzg2MDFFNzczQTZCMERCRjk0OUYzMUM5NDdFOThGRTUyQkM2QjZEODc1OTJEMUI2RUZGQUYyRDVENUM2REFBNzE4NDhBOTFCRUIyMDVCNDM2OUY5ODFCQUM2Q0MwNDM3MzZBQjA2QjVFQ0I5MDM0OTVDMjgzMDM5QjQ3OTJFOEY1RTBCNkRFRUFDMDY0NTQ4OUM5MEJGQTAyMTc2QjkyMTUzNjQzMTQxODQ2QzcyNDJDQUE0M0E0NUYwNEUwOEQ2RTY1M0YzMzE4RjMxNDYzRjZEN0JFQ0ZEQjM3NjI0RTI2MDlGRDYyN0E5MERENjExMUU2QUJDREVFRTM3MzAzNkIxNDNCMTMwQjU3NjQ4NzQyOEE2ODY0MjZCODBEMUY2MDMyMDg5OTU1Q0ZBRjE3RkQzNTg3MDZDQTIyNDE0MjhENjQ2REUzQjczOTQ1NUVBMkRFN0I5QjlDNTJGNTQ2ODEyMTdERUI1OTYyMEFEMUE2NjJEQTVFOUY4QTA4MjM0NkIwRUY5MUI4RENFOTcxRDU1MzI1ODg0NUE1MkQzRjY4M0EwN0QxNjgxNkYyQTZDMTIwREM5NDExRTQzN0I3RDkyNDc1MkJCNEU2NzU1OTRBODNGRTBCRDcxNjRENjY5QTA0NDYyQkE5NkNDNjNENjlEQjdEMjQxQTQ4RTExRkRGNjMwNTI5RjYwRjk3QTBFNDk0RTZGRTUyMEUzODc4QUVCODFGNkI4MDRGMjhGNURBQTk5RUNFMDA0OUQwMTMyMjAwQ0I2QzZFNDU0RDI1M0U1QTk5OUFCMDJERTlCNzI0RUI5MDVCQUFGNTIzMjY5QTNBQ0Q1Q0QwRkU2RkNCRUYzMUQ2RjI2MUE5NjJGRTBBNDYxQzg3ODk5Q0QzQTBCQkFFMkVCMkM3OUJDMEIyOUQxN0FBRDVBQzkzRDZDOEM4MjZEQjE0QThGMjBDMTlFMDMwRDBENTQ3ODAzN0M1MkFBOTJCMDU5NTkzMTQ5NkQ1MDVFN0RCOEY3MTA3MjE0Qzg4OEYwRTFCQ0M2MzIxOUM0OTgyRDdCODFGRUJCQzZGM0MwQTI4MjJENzA4RDdCMDc4QjFCQjIwMkZFQTE4MkQ4NkI2RTZFMkY4QzIwQzBGOTRFMThERTgxODk1MUY1NDBBMjM1OENFQTRDQzIzN0Y1RTVDQTk0RUY4NzFBNzk0QTg1NTZBNjg5QzU5NTZGOTY0QkQ1NUE2NUE1MDAzQzNCRDE4RTcxQTNBMUIyODk4NjdBN0M1MDI5OTFDQkQ2RThDMzk4RUFBOTdDMEE1OUJFRENBMjlCNzBEMzE4QkZBMjBGMzkzNUU0Q0JCMEUyQzQwNjdCNEUyREZBMEM0NjVERTdERUU5MUVBQTVBM0NBNjMzMUQzRjJEODIwN0JGMDYxNEVGQTc2QTZDMjEyMjE5RTU2QTFENTQxNUI4MzhBMUNGRUZCOTNGMkUyMjUzOUI2MkYxNkM5NzcxNzlDMTYyREEyMjcxM0NGMUE4Mjc0NTE4QjE2OEY3OTY0NDlCQUY1REJEQ0NDMjgxQzIzRTZDQjNDNUM0ODA3MUI5NjM3NjUyQ0EyOUFDMjJGQzZFODFBNTYzMTUzQ0ZFQzFCNkNGQ0VCQkM1MDE5OTc0RTE0MTZDQjk3RjRBQ0Q4ODI3REYzNDcwMkY0REE2OTVFNTJGQjMwQkM4RTMwMkMxMEY1MkZEMUVDMEQxMzNCNzhDQzdFQjU5QzQzNEMzNjI3RjkwQ0RCQzZCODQ3MjVEMUVEODVBNDFDREIxQjNFMUE4RTg1QkMxMTNDNkMzOTZCMzQ3RjlBQkFBNTdCOTdDMTE2ODNEM0RDQjZFMUNFOUNFODNERDU2MzkyQkFDRkU4OTVBMzZDMjM5ODYwOTYzQTdBM0I2MUEwNjAyQkE0MjY4QkI2N0E4ODY4NjM2OTBBMjg0N0ZCQjg1ODIxODMzNTk4QjM0NzQ0N0FCQjc4MjEyRDNCRDdGNjAzNDVEMzhGRTREMUEyRjQyOUFBMkIwOEQ4QjRDRDM2NEIzRTQxQkRGRUYzQjY3QjE4MTVBMDgwQjEyNzAzMTMyNjkxREMwQTFDREM4RkI4MEM4Njk2Q0Q4NkY5QThEODE5Njk3QkQxQ0U4RDU5NTFEQzdEQUFBRkE0MjAxNjE3M0UwMEEyRDVDREY3NEQ0MjNBMTk3NEI0OUE5RjhEQkMwNjAxQzNCNTY2QTczQkJEMTA4NTY4MDFERTcxOEE3MTEwNTAxM0ZFREY3RTIzREEzQzBCMkY3Q0YyRTBGNDcxRjNENjAxRDBBNjZEQkVGQTBBREEwOEU5NjM4NkVFMENCN0U1RUFDOTY1MjA0QjUzMDA5REIzQUQwQTkzODM1RjI0MTE4RDBERjQ4QkRGQTU2MThEMDg3MDJFMTc1OTkwQTE4OUU0NjNCNEQyQjUxMjg1Q0E0OEM3MkQwQjFCRDI4NkNDNjA0QzMzRkFDQzE3NEFFQTE2RTgwODczMkFCNTI4QjUwMjgwOTZDMzJFQUQ2Mjg3N0M3NjdGQUE1NzgxN0UxNzAyNzRDMDk4MENEMDYzRUVFNTI5QTg1RjJFMzc0QkFFNkVCRUU3Q0YyNjczM0VFREVDMThBNTMzQjhBNDY0NjEyN0Y4NEJFMTY2Njg4OEIyRTk4NzI0NDBDQjBFQUZBMjQ0QzgxMDA4RDQxRTJCREUwOTVDOTREQjQ2MzBDMDNDNkMwRThBNkZCOTE1Q0VFODRCQUEyRENFNzJGNkI3RDJGNEE5NEJCMTRFNjNERDIwNEIxRkVEMTJBMURGNzQyNUE5QjAxQkQ3NzM5RUI4MzBDQjhBOTk4RERFMjEwREI4OUYyNzAzRTIxRkRFQjkxRTFGRjYzMEE3MTA5OTYwNUFBRUI3NTIwNUYwN0YxQzdFOTA0NzQ2MzhBNkMzNDExRTk1NTZBMzRFNjcyNDQwQTRCRjA1QzE4MkE4MDRGQ0FFMUVDQTc1QTNDNTNENEFGRjNGRkVFRDcxNjVFNUI4QzU3RjQ0ODY1NjcwQ0ZBN0IxMkE2QTYzRUQ0ODU0NTMwRDZDRjJBMjExQjExRTg1RDM2NzQzMjM1NzgwQzlCNjUwMTAyNkE3OTEzNTZGNDgxNEQzNDA4RjUzRTczMjU2NDMzRTY2NDA5OTM5MTIxQzNGREU1Q0E2MTk5MTEyRUNDNjE5ODkxMUY2OUI2NkVCOTlGREREQ0Q1NjJDQkM0Q0QwREFDNEEzMDU3ODBBOTQ4QkNGMzVFRjhBMkY1MzUxNDY2MTc1RjU1QkNGOTFGRkM2MDU3NjJCMURDMUFBMTdFMEVDMkRFQjQ3OTIwQTk0NTg5QURFRjYzNTc1REE0OEZFMkU5ODY4MERDNjM5NzZGM0RDMEJDOTEyODhDOUE0MTcxODRGNjhENzFGQkU4Q0ZGNEQ5RTY3QjlFMDQ1MEU3MjZCQjE3OTMzOEU2QzNFQzUxRjI2OEQ3Njk0QkJEMDNCMEI2OEZCMzNERENCNEMwNTlCNTJGQkE2NzY0NTIwREYwN0NDRDNGNzE3OEM4NEMwQzZGN0QxMkZBNDY0MzhCMjQzQ0JDNzhEOERFOTYwNDQ0MzhCNDJENzM2MDA2MkI0QTk5NjFGOUMzMUQ0OTJFMENFRTg0NzY0RDA1NTNFOTgwNTdEM0Q5NUM0OUIwNUU2MDRBMDNGMjg1QUVBRUYxNkJCNzY2MTQ0NkM1QjJFMkQ1NjM3QURBRkMwMzEwQTQ0QUJDOUU2N0I4RjgzNkY3ODAwMjZDOTg4NThCQThEQTBFRDg5OUUwMUE1REEyNkIyRDhCRjlDQ0VFOTg0RDkxNjgwM0M5NUFENjA0RENERjExNjMwNEI3RTgyN0NBN0M3RjlCN0IzQTgzNUQ2NThCRUE5MDE1MjVEREYxMkQxQjQ5MzlDRjlGMTE3OTVEMEY5RTc2MTkwQzRENEQyNjY5ODhFMzY1RUFEMzhGRTUxRkIwNzQ4NDRDOEZCNkRCRERGRUUyMjUwOTJBQTJCODYyM0ZBQkFDMzlDRERCNkUyMDYyRjAzODVFMUYyRDgzOEU3MjkyQzE2NzFGMEFFRTdGM0RCNUNERjlDOEUzODVDRDVBQjAzQTU4MDgxMEFDRTc1MzU1QzNBMzM3M0YzMjY4QTFEQTgwN0NCQjM4MDFBQzJDNTQ5NDhEOENBN0FDMUM1RjI1MjEwQUQ0NzA4NDk4REYxMTVBMTFENkU4QTk5MzFDNDc5NDY0Rjc4NUY4N0I3OUJENEIzQTAyMDFBMkRFMDU5NEQ5NkZDN0E0QUUwM0FGQjg1N0E2MzFGMDBCNzIyQjEwN0U3NTRDMzhCREIxRUJEN0ExRDAxRTE5NENCQ0VCMjREREVDODlDRDY0NDhGQTkzMEU3QkU1QzZGNTlBMTNBMEY5QzkzNTJCRjNGMDNERjZGMEFFMEY4NjhBNTZBQTI2RTBGMzU2OUY4RkQzNzZFODE2QURBNzc4MDNDREVFMEM3QjlBRUQ4MjBCM0E1QTI4NDdBRkYxRkJFNEI0MzUyODFDMkQxMTIwMkE1Qjg0OTQ0MkNBNTg4QzYwN0Y1RUExREJCQjY2ODUyRTg0QUQzRDlGNjBBOTdERkE0RDEwNjBCQ0RBNjMwNUIyQjg3NDQ0NDVENjlEM0FDQjg5NjZGMjgwODdEMkUzRDcyQjgzOTZEQ0JCMUM4QTc1M0I5OTg5QTlDQTk3QzlEQjc0QkE3NDk2OEE5QUQ2MDRFMjNBNjVGMjBCMTVENzcyRjAyMTAxQTkwNjMzQjQ4MUYyQUNDNkIxQ0NBOEI1NEVFNUI0RDVERkE5QThBRUM5OTZEODhFNUYxQzk0QUI4RDUyMTc4MEJCMUI5MEYwQTIyOTBGN0UyNUU5NzZGNDVENkVCNEUzQUZGODkyMzU4OTNCQTk4MzdGQzc4M0Q4OEY0RjNCRUQ4NDY3REY1RDYzM0M1OTBGRDgwODBBM0EyREJFOUIwQTNERkU1NkYxNTREMzAwRUE4MTdCMjAyODQ1RUFDMDZGMkM2RDdBMkMwQ0U5RkJCNTA0QzRBNEIxNTgzQjI2OUM0OENEOTkzQjREMDc2MkNCODM2QTFBMUJGQkY2MTRFOEYzQTlDNzEzOUUzMzZDRjRDN0VFMDc2MDRCNzY2NDZFOEJENTdCNjdDNzlDNUM0QTlENTNCMjdEMkM3NEQ4NEUxQUNEQzk0MkIxQTAyQjU2REZFMTVCREU2MzE2MTQ5M0I3OUQ2MTZBMUU1QUEzMzlFM0RBRTRGMUU2MjczOTBFODY5NEIyNjVCRkQ4RkRBQTgzREIzNzlCOEYzOTVCNkYzN0IzRjk4RDREOURCRkIyMzAyNEJENDVFREM1NjRFQzc5Njg5NjFFMUVCQzVDREU0NjFFMTkxOTFFMzlFNTJCQzdEQzA3RUM5QUZCQTU2N0Q4NDlCMEY0QjkxQzEwNjA0QTg0N0ZBMDc5RERGRkE5M0E5Njg0RDNCQzBDQjQ4Q0Q1QkZEQkQyMUI1RTUxNzczNjIzQUZGMjBCNEJDODAyQjI0MTM3MzhBQzBBNkM0NEY4NUE1ODQ0NjE0RTlDQTI5MkY1QzZCMkE1ODE4RDEyQTA2NkFBMkY5N0U0NDZDMjhDNDZBMDUxMEE0RTE4NDlEQjA4MjYzQjJEOEYxQ0Q0Q0NFMjNBNjBCQjVENTkwQjY4MTNERThENTAzRTE5MDU3QzcyREQ2NjgzQjFDQ0ZDMTIxMTI4MzBENTBCQjQ3QUUwNTQxMjVCOUY1RTk4QjNCQTdFMkU3NDQzNUQyQjBCQkFFMTU0NjJDMjYxQUNDODdCQUZENjg4Q0UzQzgwQzgwRDdCM0U4RDhGOTJGNUM4RDcxMjlEQThFQUQ2MDM4QjZCRTczRUJCN0FCQTI2M0VCNUUxNzU0NTU1MUE3NDUwMjVCNjdFMzY1QzlENjkxOEI5QjgxODlCOTQwRDhDMzNEQzlGNTkyMjQwM0EzOUREMjQ2NjM0NjA5NENCODI0RTBDNEEyRjRFNTUxQUJDOEMxMkZCMjI3MEQ2MUIwRjkyRDBFQUM5RTc0MzZGOUM1MDVFRTkwQzQ5MzYxRDk1RUQ4QTRFNTIzNjBEMDU2NzlDQzI3MTI5OTZCMTlFNDg4QzE4Q0NDNjE3Q0JFQTk4QzZCNkI4QTdBMzk1RUIxQzA3MUM2Rjc0OUU0NUM0MUFCNjREMTBDN0U4QUMwNUMwQjUxQTE3NTdBQjYwNzgwQkFDRTg5M0ZGNzA5ODI1QzI5MEYzMzIwNDQ1MjhGMEQxODA0OTYyNDhFRjQ0QTFGQ0NGMTY0REM1MERGMTMwNEFGMTJCNDM3MUVBQUVCOUMxNDAxQkQ1NTNFOTlGOTI1NTdFRTJBQzIwRjM4NzdERDcyNkUzRjk5Mzc5QjY5RTU3QTUzQjA1RDI2NTNBQTc2NEMyNkQxRjJGNUZFRUM3NEY3RUJDMEIzNkU0OTJEQTBGMUYwREI2QkU0OEMzQURCRDJDRUFCNTRBMzMwNUE1MjFEMkVFRjE0MDlERUMzNjc1RTdCNTUwNjM5QUM5MEE2RUY1MzIxNjRGMkY1NEVFMUExMzg4RkI2MzIzQTBGQzdFQjA1MzgzRTlFQUJFQzU0QjQyNjhENEM1MDFBNkQ4MTM2RkI2OTZFQkEzQUIwMUE4MDUwNzkwNEUxRDJGREM3MzA0REU3MEMxN0MyMjg5MjNENjJGOEVFNEM3MzMxQzUyRDU2MEVDQkE1RTU3RUQ3NUM4ODRDODgxQkYzQTZBRjk0MTk2ODI0OUZDQjFCQ0JGRUNFQkQ5OTUwRDVERUE2QkE1RkQ5MDBGMEYzM0RFNTdGMDAwQTEwMDYxMTE4NzMyRUYyRTA5RDI3NjMwNTc5Mzk1MTE5QUZENDk0RDBBNUU5NzA1RjdGQ0Q5RTMzMDNFMzk3NTFEM0EzREI0QzJDOUI0MUVDRjg3QzY4QjYzNUNCRjQ0QzY4Q0RENjAxNDlEOTYyRkE2MDZFNEY4RUE4ODY1MEREQUZBQTBFMDJENDcyQTBFNzYxOEJEMjMyMjdBQjNGMTlFNTIwNEEyOUIzMjQyQTVDQzk1RTQ0MjlCOUY5MTVFMEExRDY3MTYzNjc1RTI3MDUxOUE0Qjk4NjE0NDdCNEY4MDMyQTQ2NkU4ODc0QTI3REU5OTRGRTYwOUM4M0JENjRDNjRDMTlEMjk3MkNCNUQ4QzQzNkM1Mzc0NkU1QUI0NzI2NTZBRUFGOTNGM0MwOEFCRkYxRDUzQkVGNDEyREU2MDQwMDc0NDVFMUZCRDM4QTlBN0ZCMUUxQjU5MEI0QjQ1RTg5MkMzMzdCNENBN0IzNUM0ODQyNDQ2ODQ3OEFDOEZEN0FEOTQxQjE3MEY2RDUzNzQ5Q0M1NTU4NDVCREEzNTRGQUYyRUQ0NzFDNDdFNjM5RDk5REY4NTI2MDUxMzM0NEQ2MjcwRTExNzRENDQ3MDQ2NTA2NEMyRjBFOTNEREFGQUMyMEFDMjBERjk0NTA2NzQ2QjEyQTRFMkQ1QTk0QjY0RDUzNEMyREU4MTVFQzBGQjI5NTEzOUNGMkFBMDdDODUxMkYzMjY0NkU5RTNFRTc2NjU4NkRENTUzRjBCNkY5RkY2Qzk5OEI0MURDMTE0NkQ2QzlDNEM3QUE0NjcxNzUzMDY1NjQ0NUQxOTk2QjY5RDY1M0FERDM3NjQzMjgwNjU3MTU0Nzg5Q0RENUM2NEE4QTFGMkY5MjQ3NEI1MjI5QzNGODkwOEVBNTBBRjY5RUNFQzU4MEE0MEY3NjYwMURCRUU2RTg5Mzc1MzY5QzIwNjg2MkI1MkFCOUEwMjI5ODNCNjIwQjU4QjZFMTNEREZENkVBNTVBQ0EyOUExOTZGRTA3NzYxQzdENDUyMjlCMzY5OTU1NUU5MjA0QTBFOTdFNENDQzA0M0E4NzI0NENCMzREMjA0MDZFNDQ4MzJEOTg5QkIxMjFGOTZFOTQ5REYxRkQ4ODE5REE2MDAzRTM5ODg1QUNFNDY2RDEwNjFGNDkzMDAxOTAwMEMxNUFENjlFOTE4MzgwMENENjQxRDYxMDA4QkRBQzQxN0ZFNjBCNEQ3NDE3RTQ5NzRDMzk0QzEwQjhFODQyNDYwRDRGMDFDMjUzQkFBQjU5RThDNTdDN0ZCMDlGMzE4N0VENkQyNTNDNjkwODg4RjAzMUE1QkZERERDNDMxOEI0MkE5NDhDM0FDQTk1RjE3QzhFQkQ5NTA3RTE3ODkwQkVCQUNEQUJFRUMxQjJEOTUyNUZDNTkxNEQzRDRBN0IxREIyN0IxNzM3QkRFNzAxMjA2OUM4MkM0NDA4QUIzNDBDOTlDRDJGODRBMEEzRUM0RUU5NUEwQzc0NzBCMUI3RkJENjJBMzNCOUQzOENDRjcxOEQwMjYzQ0IzNEMxRUQ4QkE1QjcyQkY3MjIyN0RGQzk3MDQ2RTU3REIyQ0Y4MDRDM0ExMzdERjlCNzhGNzYwNkE1MTY5QjdCNjhBQUY0MzhFQjMwREZEMjE3MTZFRUE5NkE1NEI2RDVEN0RERThCNkI0QjlGODUwMDQ3MzcxM0MzNjA3QkE5NzMxMUI5NUQ1MjFBNjBDNDVGRjY4RjBEQkMwMDE5QzNDQThBMEUxQzgyNENCQzA3MzNCMkI5QjY3Q0U0OEEwM0IyM0UzRDAzQjJENjBBMjREMTcxRkUxM0FGMjZBNDRBN0JFNEVDNEE5RDdFQ0I5QUM4NzgxMTMzQTAxMzcyNUZBQTY1MTEwMDFGNTBFQjhENzlBQTRFMDUyQjY2OUMwODY5NzNFRjQyNkQ2NkFGMEM0RDM2ODZBMEQxMkU1QzA1NUE0OEZFRkVGNzkx)

- Once you recognize what algorithm is used to decrypt the shellcode, all you have to do is to find out where does the input args resides in the coredump data/memory (offsets within the file raw data). This can be done both statically with a binary analysis tool (**the coredump is an ELF file**!) like IDA PRO or while debugging with a tool like `gdb` .See [Kazuki Furukawa writeup](https://gmo-cybersecurity.com/blog/flare-on-11-write-up-ja/)

## The dynamic way - Take advantage of the binary code at hand

### Emulation

#### With Ghidra (p-code) emulator using a ghidra script

[See Washi's writeup](https://washi1337.github.io/ctf-writeups/writeups/flare-on/2024/5/#decrypting-the-code)

- Notice that he had to first "**mmap**" in Ghidra (**"Add memory block"** of size **0x100000** at a non-mapped addr **0x13370000** , **RWX permissions**, **uninitiallized**?. seems like had some block address conflict) an area to include both the `"from"` function's parameter **content**, **and memory for temporary and final output/return value of the function**.
  He somehow copied the **from** content from gdb to the mmaped area **but didn't mention how** [see content here](https://washi1337.github.io/ctf-writeups/writeups/flare-on/2024/5/img/09.png).

    @**TODO**: perhaps some kind of memory editing while debugging?
- Then making a ghidra script (java in this case or python): [See washi's code](https://paste.ofcode.org/SPeYmRXccCTksEWftRrBxa)
  - Other than the cryptic syntax for reading from a memory address `(emulator.readMemory(emulator.getExecutionAddress().getNewAddress(STATE),size)` the rest should be clear to you.
  - note that execution is done in two non-consequtive instructions parts such that only the chacha related functionallity will get extracted.

### Pure execution as is of the assembly code (because we can run it native)

#### Using `dlopen()`,`dlsym()` etc

@TODO: how easy is it to achieve the same with with frida? (as far as I remember this should be easy)  

**This is perhaps the most straightforward and fastest method**,
requires us to set **only one array** of bytes at minimum.  

Examples:

- [cano32 code](https://paste.ofcode.org/XB8RR2TRw2zSLF2XPRsFY7) taken from [here](https://cano32.github.io/writeups/FlareOn11-2024)

#### Using the sshd binary

not practical in this case, it has many unknown arguments and it's not that straightforward to invoke the required function (and thus loading the liblzma library into memory)

#### Using LD_PRELOAD trick

This is **a more convoluted and unneccesary method** that I've used for no good reason. (dlsym failed for some reason)
looking for liblzma in `/proc/self/maps` and then calling `RSA_public_decrypt`, see attached code [xpl.c](my_files/xpl.c)

or with `pwndbg`:
`$ LD_PRELOAD=./liblzma.so.5 gdb xpl NOASLR`
the decrypted shellcode is written into the same memory of the original array by the function.

# understanding the shellcode

## reversing it

- `oxdf@hacky$ strings -n 10 shellcode`
  ---> `expand 32-byte K`
  (note "K" rather than "k")

see for example [Washi's writeup](https://washi1337.github.io/ctf-writeups/writeups/flare-on/2024/5/#analyzing-stage-2)

### Fixing the syscall decompilation

Fixing the code such that decompilation will show the syscalls names

#### In **Ghidra**

run `ResolveX86orX64LinuxSyscallsScript.java` script in `Tools→Script Manager`.. (may need to edit the script to exclude the ELF header check)

#### In IDA

- You can try loading ELF header file
- You can try `loading as an additional binary` the (raw) shellcode into `liblzma.so.5.4.1` at a custom available addr like in [this video (jinmo123)](https://www.youtube.com/watch?v=WLSZPC5ZagY&t=671s) - he types so fast it's hard to see what he does, use 0.25 speed
  - I guess this works thank to the fact the **liblzma shared library** is (**dynamically** in this case) **linked** with: `libc.so.6` and `linux-vdso.so.1`(for optimized syscalls) which includes the required definitions.
  
## dynamic analysis

You would probably need to wrap/load the shellcode [within an ELF](https://github.com/stong/flare-on-2024-writeups/blob/master/5-sshd/lol.c) or exe (e.g `shellcode2exe`)

`sudo strace -u root ./test` to see what syscalls are called each time  

`sudo strace -u root ./test -e trace=network -f -d`  
 (network syscalls only, follow child process, include debug output)

# Finding the offset of the encrypted flag content

Coredump static analysis:  
[ImHex](https://imhex.werwolv.net/) includes a full custom C++-like pattern language that allows easy highlighting, decoding and analyzing of file formats.

using the shellcode and some test input, the **encrypted file contents are stored 256 bytes higher in memory than the ChaCha structure**

# Methods for getting the flag

    Instead of analyzing the shellcode as standalone, we patch into glo_ciphertext to have the correct offsets:
    Once we load it in IDA, we'll need to set the base address to match when the crash occurred.
    To do this, we can display all the info about the loaded shared libraries by info sharedlibrary in gdb:

```log
(gdb) info sharedlibrary
From                To                  Syms Read   Shared Object Library
...
0x00007f4a18c8ad40  0x00007f4a18ca8d26  Yes (*)     ../ssh_container/lib/x86_64-linux-gnu/liblzma.so.5
...
```

The From address represents the start address of the `.text` segment. To get the base address, we can use `readelf`:

```shell
(base) joe@FlareVM:infected_liblzma$ readelf -S liblzma.so.5.4.1 | grep .text
  [15] .text             PROGBITS         0000000000004d40  00004d40

(base) joe@FlareVM:infected_liblzma$ python
...
>>> hex(0x00007f4a18c8ad40 - 0x4d40)
'0x7f4a18c86000'
```

You can also caluclate the offset to the function where the crash happend (`0x988f`)
Even though the shellcode has been re-encrypted, the parameters (key, nonce, filename_size, filename) are still in the core dump

You can also look for the opcodes executed before the crash and search them in the `liblzma.so.5.4.1` dissassembly, but a image rebase (for base addr) is an good idea anyhow.

See for example [HERE](https://washi1337.github.io/ctf-writeups/writeups/flare-on/2024/5/#finding-the-relevant-code) how it can be done with Ghidra when loading the file
As an alternative, you can rebase to 0x0.

      I’ll open the library file from the container in Ghidra.
      I’ll set the base address to 0 in Window –> Memory Map –> Home icon, 
      and then move to 0x988f (where the crash happend)        

looking for file paths inside the coredump can be done with something like:
`pwndbg> search "/" stack`

you can send (from server) your own encrypted file, key and nonce to the client running the shellcode and search in its stack memory for these bytes to find the offsets needed to extract them from the coredump.

**stong/cts**:

    We are lucky the corefile was produced right after this shit was sent,
    so all the data we need is still just chilling on the stack.
    This is why it's hard to do crypto right; 
    here the best practice would be to zero key material from memory after use,
    but they didn't do that. 
    
    Since chacha20 is a stream cipher, one interesting observation here is that 
    decryption and encryption are the same operation:
    given the same key and nonce, they use the same keystream
    which is simply XORed with the input.

## The EASY method for finding offsets within coredump of the data needed for us

find the offset to `"/root/certificate_authority_signing_key.txt"` and use relative offsets to it to find the rest of the chacha20 parameters.
You can also search the coredump for the magic 4 bytes: `\x48\x7A\x40\xC5`

## The SLOWER and harder method for finding offsets within coredump of the data needed for us

**Important Note: for this method, you must understand how stack ($rsp,$rbp), CALL and PUSH works under the hood in x86 architecture**
from [SuperFashi writeup](https://gmo-cybersecurity.com/blog/flare-on-11-write-up/):

    So we just need to recover the data from the stack, again. 
    This time it is slightly more complicated, 
    **since the function we are looking at is not in the frame**,
    so it would take some effort to calculate the correct offset of the stack address.

[He shows **an almost full explaination** on how to calculate the addresses in memory](https://ibb.co/HX5hxvc), (the value of `RSP` decreases by **8** (64bit address space) during the execution of `CALL`, such that the return addr can be stored there)

- Thus, when you see people in their writeups substituted `$rbp` with `$rsp-0x40` , it's because of a total of **8 push opcodes** (**2** of them are **embedded within a call instruction**) before reaching the shellcode **which doesn't modify the stack layout!!!, note it doesn't follow a normal calling convention and doesn't have the `push rbp / mov rbp, rsp` at the beginning**, that is also why some people modified in IDA the function type ('Y' hotkey) to `__usercall` to help it decompile.s
  - [see image here](https://ibb.co/5MLhgvL) allowing us to use `$rsp` from **frame number 1**

- For example, in [0xdf writeup](https://0xdf.gitlab.io/flare-on-2024/sshd#get-values), note that `0x1f4c18` is the offset of the string inside the ELF raw bytes and that he adds `0x1148` to it to get the relative position of $rbp for that specific stack frame. **But he gave up on solving by using chacha20 allegedly because he couldn't find the encrypted content.

- Another example for manually finding each parameter/field using offsets: [Link](https://hackmd.io/@huydeptrainhatvinhbacbo/flareon2024#Challenge-5-sshd)

- see also calculations here at the buttom: [sec.vnpt.vn blog](https://sec.vnpt.vn/2024/11/flareon-11-writeup-part-1/)

### Finding the encrypted content length (whileas not neccessary)

- if you debug/strace the shellcode, you will notice that the shellcode will read **0x80 bytes** at most from the file
- you can try to stop on null byte. works only due to the type of the cipher, see next
- extracted as many bytes as you want since it's a **stream cipher**
(as opposed to a **block cipher**) you can decode as many as you want and throw away anything that looks like garbage. In other words, you just need to extract enough characters for the flag.
- **The actual design** of the protocol: it's embedded within the user **struct**, see [image from stong writeup](https://ibb.co/wz8mFYR), **thus 0x20 is the flag length**

## Emulation

For reasons like not recognizing the modification from 'k' to 'K' in chacha20 and other reasons, some people preffered to try emulation

- **Note that in this way, we don't have to seperate between different parts of the consequtive in memory chacha20 struct data**.
  - (see [angr solution](#angr)) which uses two blocks of raw data from coredump
  - In [Jinmo123](https://youtu.be/WLSZPC5ZagY?t=3621) [Unicorn](#unicorn) code (ignore tha crypto code, he didn't use it) he simply copied one big consequtive block of raw data from the stack and it worked (luckily)
**Note that with emulation, we don't need to mind the encryption algorithm but just find the entry point to where decryption happens and set the needed input to it**

### Qiling

see [qiling vs other frameworks](https://qiling.io/comparison/)
possible to solve with it (both decrypting the shellcode and executing it), though if you want to avoid implementing a c2 server you will need to hook the shellcode's network syscalls as well.

to be updated with example code...

### angr

- **What's nice about this one is that we don't need to manually mmap in the code**
Example: [code by superFashi](https://paste.ofcode.org/ujJzyvRf7KQTRiFK8mJGrX)
@TODO: Understand the code

### Unicorn

- [Jinmo123](https://youtu.be/WLSZPC5ZagY?t=3621)
- [Code by Tosbaha](https://github.com/tosbaha/reverse/blob/main/ctf/flareon%202024/05/solution.py)
- [code by sud0woodo](https://gist.github.com/sud0woodo/a22c9f96ece8e7bdf19c0ffbe7654fde) - somewhat weird fixes ("@")

## (dynamic) modifying stack memory and registers while debugging (gdb etc.)

[Stong/cts](https://github.com/stong/flare-on-2024-writeups/tree/master/5-sshd)

    Then, I breakpointed the start of the shellcode, and stepped through it manually.
    Each time it would do a syscall, I would just manually update the memory or registers in gdb to simulate 
    the syscall reading the parameters (key, nonce, flag contents, etc.) from socket or disk.

I guess you can also do some massive "automatic" hooking with **frida** to acheive the same

## (dynamic) Writing code which mimics a C2 server to talk with the backdoor client

- Relies on the fact that the encryption/decryption process ("custom" chacha20) is identical in both ways
  - It will send the client the according to the custom communication protocol the (encrypted) data (path string and the path string len), key and nonce data which can be found within the coredump file at specific offsets. and will receive back the decrypted (original) flag file content
    - In [Kazuki Furukawa writeup](https://gmo-cybersecurity.com/blog/flare-on-11-write-up-ja/) Only part of the process is shown (just the c2 server code, but not how to run the backdoor shellcode).
    - [somewhat too long code in python](https://github.com/hasherezade/flareon2024/blob/main/task5/server.py)
    - [same idea python](https://github.com/ispoleet/flare-on-challenges/blob/master/flare-on-2024/05_sshd/sshd_crack.py)
    - So we need to listen on port 1337. But it’s expecting to connect to 10.0.2.15. No worries, we can change that with iptables.

```bash
sudo iptables -t nat -A OUTPUT -d 10.0.2.15 -p tcp --dport 1337 -j DNAT --to-destination 127.0.0.1:1337
sudo iptables -t nat -A OUTPUT -d 10.0.2.15 -j DNAT --to-destination 127.0.0.1

nc -lnvp 1337
```

```bash
sudo ip addr add 10.0.2.15/24 dev eth0  // set ip addr
ip addr show      // verify ip addr set
```

- You will need to somehow run the shellcode on the client side (shellcode loader)
  - [hasherezade cpp](https://github.com/hasherezade/flareon2024/blob/main/task5/shc_runner.cpp)
It can be implemented in C as well, see [code at the buttom](https://csmantle.top/ctf/wp/2024/11/09/ctf-writeup-flareon11.html#5---sshd)

Appendix  
--------------------

Refer to the chacha20 key and nonce format here:
<https://xilinx.github.io/Vitis_Libraries/security/2019.2/guide_L1/internals/chacha20.html>  
<https://www.uptycs.com/blog/threat-research-report-team/rtm-locker-ransomware-as-a-service-raas-linux>  
<https://ar5iv.labs.arxiv.org/html/1907.11941>  
<https://zenn.dev/mahiro33/articles/40d0efb0b5b32a>  
<https://github.com/Ginurx/chacha20-c> (don't forget to change "k" to "K")  
<https://github.com/spcnvdr/xchacha20>

Emulation with ghidra:  
<https://syscall7.com/machine-emulation-with-ghidra/>  
<https://github.com/HackOvert/GhidraSnippets?tab=readme-ov-file#emulating-a-function>  
<https://documents.trendmicro.com/images/TEx/pdf/Technical-Brief---LoRaWANs-Protocol-Stacks-The-Forgotten-Targets-at-Risk.pdf>  
<https://www.youtube.com/watch?v=xz5qHmc41LI>  
<https://github.com/Nalen98/GhidraEmu>  
<https://bienaime.info/media/sstic2020_bienaime.pdf> (french)  
<https://wrongbaud.github.io/posts/kong-vs-ghidra/>  
<https://samg.uk/rp2040/emulating_rp2040.html>  
<https://medium.com/@cetfor/emulating-ghidras-pcode-why-how-dd736d22dfb>  
<https://www.danbrodsky.me/posts/ghidra-gang/>
