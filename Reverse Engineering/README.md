# Reverse Engineering

At: [TryHackMe](https://tryhackme.com/room/reverseengineering) By: [ashu](https://tryhackme.com/p/ashu)
</br>
*I strongly recommend reading this on a PC on fullscreen.*

## crackme 1

Right, so lets download (chmod +x) and run:
```
enter password
adawdgaywai
password is incorrect
*** stack smashing detected ***: <unknown> terminated
Aborted
```
Few, okay. What shall we do now? Run `strings` or `ltrace`? Lets try ltrace:
```bash
$ ltrace ./crackme1.bin 
puts("enter password"enter password
)                                                                                                       = 15
__isoc99_scanf(0x561f049cb8a3, 0x7ffe8f44a3a2, 0, 0x7f741e41e643smth
)                                                            = 1
strcmp("smth", "*****")                                                                                                      = 11
puts("password is incorrect"password is incorrect
)                                                                                                = 22
+++ exited (status 0) +++
```
aight. First one down. Could we have gotten with strings as well?
```
$ strings crackme1.bin 
/lib64/ld-linux-x86-64.so.2
libc.so.6
__isoc99_scanf
puts
__stack_chk_fail
__cxa_finalize
strcmp
__libc_start_main
GLIBC_2.7
GLIBC_2.4
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
=y	 
=9	 
52	 
AWAVI
AUATL
[]A\A]A^A_
enter password
password is correct
password is incorrect
*****
...
...
```
Indeed we could. Onwards!

## crackme 2

Same like last time:
```bash
$ ./crackme2.bin 
enter your password
password
password is incorrect
```
So strings and ltrace?
```bash
$ ltrace ./crackme2.bin 
puts("enter your password"enter your password
)                                                                                                  = 20
__isoc99_scanf(0x565087983838, 0x7fff6d93ed54, 0, 0x7f97d0b9a643password
)                                                            = 0
puts("password is incorrect"password is incorrect
)                                                                                                = 22
+++ exited (status 0) +++
```
Okay, not this time. Well I guess we'll have to reverse it. I'll be using r2:
```bash
$ r2 -d crackme2.bin
```
Once it loads enter `aa` to analyze all and then `pdf @main` to show the assembly of main:
```C
$ r2 -d crackme2.bin 
Process with PID 2241 started...
= attach 2241 2241
bin.baddr 0x556afad8a000
Using 0x556afad8a000
asm.bits 64
[0x7fbaa369d090]> aa
[x] Analyze all flags starting with sym. and entry0 (aa)
[0x7fbaa369d090]> pdf @main
┌ 122: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_ch @ rbp-0xc
│           ; var int64_t var_8h @ rbp-0x8
│           0x556afad8a71a      55             push rbp
│           0x556afad8a71b      4889e5         mov rbp, rsp
│           0x556afad8a71e      4883ec10       sub rsp, 0x10
│           0x556afad8a722      64488b042528.  mov rax, qword fs:[0x28]
│           0x556afad8a72b      488945f8       mov qword [var_8h], rax
│           0x556afad8a72f      31c0           xor eax, eax
│           0x556afad8a731      488d3dec0000.  lea rdi, str.enter_your_password ; 0x556afad8a824 ; "enter your password"
│           0x556afad8a738      e893feffff     call sym.imp.puts       ; int puts(const char *s)
│           0x556afad8a73d      488d45f4       lea rax, [var_ch]
│           0x556afad8a741      4889c6         mov rsi, rax
│           0x556afad8a744      488d3ded0000.  lea rdi, [0x556afad8a838] ; "%d"
│           0x556afad8a74b      b800000000     mov eax, 0
│           0x556afad8a750      e89bfeffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│           0x556afad8a755      8b45f4         mov eax, dword [var_ch]
│           0x556afad8a758      3d7c130000     cmp eax, 0x****
│       ┌─< 0x556afad8a75d      750e           jne 0x556afad8a76d
│       │   0x556afad8a75f      488d3dd50000.  lea rdi, str.password_is_valid ; 0x556afad8a83b ; "password is valid"
│       │   0x556afad8a766      e865feffff     call sym.imp.puts       ; int puts(const char *s)
│      ┌──< 0x556afad8a76b      eb0c           jmp 0x556afad8a779
│      │└─> 0x556afad8a76d      488d3dd90000.  lea rdi, str.password_is_incorrect ; 0x556afad8a84d ; "password is incorrect"
│      │    0x556afad8a774      e857feffff     call sym.imp.puts       ; int puts(const char *s)
│      │    ; CODE XREF from main @ 0x556afad8a76b
│      └──> 0x556afad8a779      b800000000     mov eax, 0
│           0x556afad8a77e      488b55f8       mov rdx, qword [var_8h]
│           0x556afad8a782      644833142528.  xor rdx, qword fs:[0x28]
│       ┌─< 0x556afad8a78b      7405           je 0x556afad8a792
│       │   0x556afad8a78d      e84efeffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       └─> 0x556afad8a792      c9             leave
└           0x556afad8a793      c3             ret
```
Very cool, so what can we see? 
```c
│           0x55cfcf75b750      e89bfeffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│           0x55cfcf75b755      8b45f4         mov eax, dword [var_ch]
│           0x55cfcf75b758      3d7c130000     cmp eax, 0x****
```
Right after calling `scanf` which takes our input, the input is then moved into `eax` and compared to `0x****` just simply convert this number to decimal and we have the answer.

## crackme 3

`What are the first 3 letters of the correct password?` Sooo, we aren't looking for the whole password. Cool, time for `r2`.

```bash
$ r2 -d crackme3.bin 
Process with PID 2611 started...
= attach 2611 2611
bin.baddr 0x55999c910000
Using 0x55999c910000
asm.bits 64
[0x7f249fa21090]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for vtables
[TOFIX: aaft can't run in debugger mode.ions (aaft)
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x7f249fa21090]> afl
0x55999c910610    1 42           entry0
0x55999cb10fe0    1 4124         reloc.__libc_start_main
0x55999c910640    4 50   -> 40   sym.deregister_tm_clones
0x55999c910680    4 66   -> 57   sym.register_tm_clones
0x55999c9106d0    5 58   -> 51   sym.__do_global_dtors_aux
0x55999c910600    1 6            sym.imp.__cxa_finalize
0x55999c910710    1 10           entry.init0
0x55999c910840    1 2            sym.__libc_csu_fini
0x55999c910844    1 9            sym._fini
0x55999c9107d0    4 101          sym.__libc_csu_init
0x55999c91071a    9 170          main
0x55999c9105a0    3 23           sym._init
0x55999c9105d0    1 6            sym.imp.puts
0x55999c9105e0    1 6            sym.imp.__stack_chk_fail
0x55999c910000    2 25           map._root_CTFs_TryHackMe_reverseengineering_crackme3.bin.r_x
0x55999c9105f0    1 6            sym.imp.__isoc99_scanf
[0x7f249fa21090]> 
```
Right, so we have just main. Nice! `pdf @main`
```C
┌ 170: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_28h @ rbp-0x28
│           ; var int64_t var_23h @ rbp-0x23
│           ; var int64_t var_21h @ rbp-0x21
│           ; var int64_t var_20h @ rbp-0x20
│           ; var int64_t var_8h @ rbp-0x8
│           0x55999c91071a      55             push rbp
│           0x55999c91071b      4889e5         mov rbp, rsp
│           0x55999c91071e      4883ec30       sub rsp, 0x30
│           0x55999c910722      64488b042528.  mov rax, qword fs:[0x28]
│           0x55999c91072b      488945f8       mov qword [var_8h], rax
│           0x55999c91072f      31c0           xor eax, eax
│           0x55999c910731      66c745dd617a   mov word [var_23h], 0x7a61 ; '**' 
│           0x55999c910737      c645df74       mov byte [var_21h], 0x74 ; '*'
│           0x55999c91073b      488d3d120100.  lea rdi, str.enter_your_password ; 0x55999c910854 ; "enter your password"
│           0x55999c910742      e889feffff     call sym.imp.puts       ; int puts(const char *s)
│           0x55999c910747      488d45e0       lea rax, [var_20h]
│           0x55999c91074b      4889c6         mov rsi, rax
│           0x55999c91074e      488d3d130100.  lea rdi, [0x55999c910868] ; "%s"
│           0x55999c910755      b800000000     mov eax, 0
│           0x55999c91075a      e891feffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│           0x55999c91075f      c745d8000000.  mov dword [var_28h], 0
│       ┌─< 0x55999c910766      eb2f           jmp 0x55999c910797
│      ┌──> 0x55999c910768      8b45d8         mov eax, dword [var_28h]
│      ╎│   0x55999c91076b      4898           cdqe
│      ╎│   0x55999c91076d      0fb65405e0     movzx edx, byte [rbp + rax - 0x20]
│      ╎│   0x55999c910772      8b45d8         mov eax, dword [var_28h]
│      ╎│   0x55999c910775      4898           cdqe
│      ╎│   0x55999c910777      0fb64405dd     movzx eax, byte [rbp + rax - 0x23]
│      ╎│   0x55999c91077c      38c2           cmp dl, al
│     ┌───< 0x55999c91077e      7413           je 0x55999c910793
│     │╎│   0x55999c910780      488d3de40000.  lea rdi, str.password_is_incorrect ; 0x55999c91086b ; "password is incorrect"
│     │╎│   0x55999c910787      e844feffff     call sym.imp.puts       ; int puts(const char *s)
│     │╎│   0x55999c91078c      b800000000     mov eax, 0
│    ┌────< 0x55999c910791      eb1b           jmp 0x55999c9107ae
│    │└───> 0x55999c910793      8345d801       add dword [var_28h], 1
│    │ ╎│   ; CODE XREF from main @ 0x55999c910766
│    │ ╎└─> 0x55999c910797      837dd802       cmp dword [var_28h], 2
│    │ └──< 0x55999c91079b      7ecb           jle 0x55999c910768
│    │      0x55999c91079d      488d3ddd0000.  lea rdi, str.password_is_correct ; 0x55999c910881 ; "password is correct"
│    │      0x55999c9107a4      e827feffff     call sym.imp.puts       ; int puts(const char *s)
│    │      0x55999c9107a9      b800000000     mov eax, 0
│    │      ; CODE XREF from main @ 0x55999c910791
│    └────> 0x55999c9107ae      488b4df8       mov rcx, qword [var_8h]
│           0x55999c9107b2      6448330c2528.  xor rcx, qword fs:[0x28]
│       ┌─< 0x55999c9107bb      7405           je 0x55999c9107c2
│       │   0x55999c9107bd      e81efeffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       └─> 0x55999c9107c2      c9             leave
└           0x55999c9107c3      c3             ret
```
There is a glaring for loop, this is definitely a loop comparing character by character to our input:
```C
   ┌─< 0x55999c910766      eb2f           jmp 0x55999c910797                              <-- start of loop
  ┌──> 0x55999c910768      8b45d8         mov eax, dword [var_28h]
  ╎│   0x55999c91076b      4898           cdqe
  ╎│   0x55999c91076d      0fb65405e0     movzx edx, byte [rbp + rax - 0x20]
  ╎│   0x55999c910772      8b45d8         mov eax, dword [var_28h]
  ╎│   0x55999c910775      4898           cdqe
  ╎│   0x55999c910777      0fb64405dd     movzx eax, byte [rbp + rax - 0x23]
  ╎│   0x55999c91077c      38c2           cmp dl, al
 ┌───< 0x55999c91077e      7413           je 0x55999c910793
 │╎│   0x55999c910780      488d3de40000.  lea rdi, str.password_is_incorrect ; 0x55999c91086b ; "password is incorrect"
 │╎│   0x55999c910787      e844feffff     call sym.imp.puts       ; int puts(const char *s)
 │╎│   0x55999c91078c      b800000000     mov eax, 0
┌────< 0x55999c910791      eb1b           jmp 0x55999c9107ae
│└───> 0x55999c910793      8345d801       add dword [var_28h], 1
│ ╎│   ; CODE XREF from main @ 0x55999c910766
│ ╎└─> 0x55999c910797      837dd802       cmp dword [var_28h], 2
│ └──< 0x55999c91079b      7ecb           jle 0x55999c910768                            <-- loops back if condition is met
```
Time to set a breakpoint with `db <address>` and run with `dc`. Then step with `ds` and check registers with `dr`, to view variables do `px @<address>`.</br>
So I set a breakpoint right after the scanf call:
```C
0x55999c91075a      e891feffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
0x55999c91075f      c745d8000000.  mov dword [var_28h], 0            <-- here
```
I ran the binary, stepped all the way to `cmp dl,al` and checked the address of `dl`:
```
[0x55999c91075f]> px @rbp-dl
- offset -       0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x7ffd38efc0ed  7f00 0054 0891 9c99 5500 007a 518b 9f24  ...T....U..zQ..$
0x7ffd38efc0fd  7f00 0000 0000 0000 0000 0060 c1ef 38fd  ...........`..8.
0x7ffd38efc10d  7f00 0010 0691 9c99 5500 0040 c2ef 38fd  ........U..@..8.
0x7ffd38efc11d  7f00 0000 0000 0000 0000 005f 0791 9c99  ..........._....
0x7ffd38efc12d  5500 0000 0000 0000 0000 0000 0000 0000  U...............
0x7ffd38efc13d  617a 7473 6d74 6800 5500 0010 0691 9c99  ***smth.U.......          <-- smth was my input
0x7ffd38efc14d  5500 0040 c2ef 38fd 7f00 0000 1b25 8eda  U..@..8......%..
0x7ffd38efc15d  a3ec 9fd0 0791 9c99 5500 000b 5e86 9f24  ........U...^..$
0x7ffd38efc16d  7f00 0000 0000 0000 0000 0048 c2ef 38fd  ...........H..8.
0x7ffd38efc17d  7f00 0000 0004 0001 0000 001a 0791 9c99  ................
0x7ffd38efc18d  5500 0000 0000 0000 0000 00b5 4481 b4b8  U...........D...
0x7ffd38efc19d  b14d 4010 0691 9c99 5500 0040 c2ef 38fd  .M@.....U..@..8.
0x7ffd38efc1ad  7f00 0000 0000 0000 0000 0000 0000 0000  ................
0x7ffd38efc1bd  0000 00b5 44c1 3945 f984 14b5 44a7 0096  ....D.9E....D...
0x7ffd38efc1cd  b737 1500 0000 0000 0000 0000 0000 0000  .7..............
0x7ffd38efc1dd  0000 0000 0000 0000 0000 0058 c2ef 38fd  ...........X..8.
[0x55999c91075f]> 
```
So there we have it!
