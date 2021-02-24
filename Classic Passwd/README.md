# Classic Passwd

Available at: [TryHackMe](https://tryhackme.com/room/classicpasswd)
Made by: [4non](https://tryhackme.com/p/4non)

## Starting off

After downloading the binary, I ran a few checks:
```bash
root@kali:~/CTFs/TryHackMe/classicpassword# file Challenge.Challenge 
Challenge.Challenge: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=b80ce38cb25d043128bc2c4e1e122c3d4fbba7f7, for GNU/Linux 3.2.0, not stripped
```
```bash
root@kali:~/CTFs/TryHackMe/classicpassword# binwalk Challenge.Challenge 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             ELF, 64-bit LSB shared object, AMD x86-64, version 1 (SYSV)

```
```bash
root@kali:~/CTFs/TryHackMe/classicpassword# strings Challenge.Challenge 
/lib64/ld-linux-x86-64.so.2
strcpy
exit
__isoc99_scanf
puts
printf
__cxa_finalize
strcmp
__libc_start_main
libc.so.6
GLIBC_2.7
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u/UH
Made by H
4non
https://H
github.cH
om/n0obiH
AGB6js5dH
9dkGf
[]A\A]A^A_
Insert your username: 
Welcome
Authentication Error
THM{%d%d} <-- FANCY THAT!
;*3$"
GCC: (Debian 10.2.0-16) 10.2.0
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.0
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
Challenge.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
_ITM_deregisterTMCloneTable
strcpy@@GLIBC_2.2.5
puts@@GLIBC_2.2.5
vuln
_edata
printf@@GLIBC_2.2.5
__libc_start_main@@GLIBC_2.2.5
__data_start
strcmp@@GLIBC_2.2.5
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
__bss_start
main
__isoc99_scanf@@GLIBC_2.7
exit@@GLIBC_2.2.5
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@@GLIBC_2.2.5
.symtab
.strtab
.shstrtab
.interp
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.got.plt
.data
.bss
.comment
```
And running it:
```bash
root@kali:~/CTFs/TryHackMe/classicpassword# ./Challenge.Challenge 
Insert your username: 
```
Cool, we have confirmed that this is a dynamically linked ELF binary and some functions that from the `strings` output. Since we are supposed to enter a username, I tried `4non` but alas, nothing.</br>
Probably time for some r2.

## r2

r2 is a reverse engineering command line tool. Start it like so: `radare2 -d Challenge.Challenge `</br>
Next step is to `aa` which means analyse all. Give it a minute, and then do as follows:
```bash
[0x7f7b77356090]> pdf @main
            ; DATA XREF from entry0 @ 0x564a4392e0bd
┌ 31: int main (int argc, char **argv, char **envp);
│           0x564a4392e2f6      55             push rbp
│           0x564a4392e2f7      4889e5         mov rbp, rsp
│           0x564a4392e2fa      b800000000     mov eax, 0
│           0x564a4392e2ff      e881feffff     call sym.vuln
│           0x564a4392e304      b800000000     mov eax, 0
│           0x564a4392e309      e87bffffff     call sym.gfl
│           0x564a4392e30e      b800000000     mov eax, 0
│           0x564a4392e313      5d             pop rbp
└           0x564a4392e314      c3             ret
[0x7f7b77356090]> 
```
*Note: Your memory addresses will not be same*</br>
We can see two interesting functions. `sym.vuln` and `sym.gfl`. We can analyse them the same way `pdf @sym.vuln` and `pdf @sym.gfl`. Lets do that!
```bash
[0x7f7b77356090]> pdf @sym.gfl
            ; CALL XREF from main @ 0x564a4392e309
┌ 109: sym.gfl ();
│           ; var int64_t var_8h @ rbp-0x8
│           ; var int64_t var_4h @ rbp-0x4
│           0x564a4392e289      55             push rbp
│           0x564a4392e28a      4889e5         mov rbp, rsp
│           0x564a4392e28d      4883ec10       sub rsp, 0x10
│           0x564a4392e291      c745fcd5c852.  mov dword [var_4h], 0x52c8d5
│       ┌─< 0x564a4392e298      eb4f           jmp 0x564a4392e2e9
│      ┌──> 0x564a4392e29a      817dfc788a63.  cmp dword [var_4h], 0x638a78
│     ┌───< 0x564a4392e2a1      7542           jne 0x564a4392e2e5
│     │╎│   0x564a4392e2a3      c745f8741400.  mov dword [var_8h], 0x1474
│    ┌────< 0x564a4392e2aa      eb30           jmp 0x564a4392e2dc
│   ┌─────> 0x564a4392e2ac      817df8302100.  cmp dword [var_8h], 0x2130
│  ┌──────< 0x564a4392e2b3      7523           jne 0x564a4392e2d8
│  │╎││╎│   0x564a4392e2b5      8b55f8         mov edx, dword [var_8h]
│  │╎││╎│   0x564a4392e2b8      8b45fc         mov eax, dword [var_4h]
│  │╎││╎│   0x564a4392e2bb      89c6           mov esi, eax
│  │╎││╎│   0x564a4392e2bd      488d3d790d00.  lea rdi, str.THM_d_d    ; 0x564a4392f03d ; "THM{%d%d}"
│  │╎││╎│   0x564a4392e2c4      b800000000     mov eax, 0
│  │╎││╎│   0x564a4392e2c9      e882fdffff     call sym.imp.printf     ; int printf(const char *format)
│  │╎││╎│   0x564a4392e2ce      bf00000000     mov edi, 0
│  │╎││╎│   0x564a4392e2d3      e8a8fdffff     call sym.imp.exit       ; void exit(int status)
│  └──────> 0x564a4392e2d8      8345f801       add dword [var_8h], 1
│   ╎││╎│   ; CODE XREF from sym.gfl @ 0x564a4392e2aa
│   ╎└────> 0x564a4392e2dc      817df80e2700.  cmp dword [var_8h], 0x270e
│   └─────< 0x564a4392e2e3      7ec7           jle 0x564a4392e2ac
│     └───> 0x564a4392e2e5      8345fc01       add dword [var_4h], 1
│      ╎│   ; CODE XREF from sym.gfl @ 0x564a4392e298
│      ╎└─> 0x564a4392e2e9      817dfc88d077.  cmp dword [var_4h], 0x77d088
│      └──< 0x564a4392e2f0      7ea8           jle 0x564a4392e29a
│           0x564a4392e2f2      90             nop
│           0x564a4392e2f3      90             nop
│           0x564a4392e2f4      c9             leave
└           0x564a4392e2f5      c3             ret
[0x7f7b77356090]> 
```
Nice! We can all see the flag, right? Well dont get too excited, look back at `sym.main` the code execution has to get there, we cant just make the instruction pointer jump over here. Oh, and all those arrows, dont worry, its a for loop.
```bash
[0x7f7b77356090]> pdf @sym.vuln
            ; CALL XREF from main @ 0x564a4392e2ff
┌ 260: sym.vuln ();
│           ; var int64_t var_2c0h @ rbp-0x2c0
│           ; var int64_t var_23eh @ rbp-0x23e
│           ; var int64_t var_236h @ rbp-0x236
│           ; var int64_t var_232h @ rbp-0x232
│           ; var int64_t var_230h @ rbp-0x230
│           ; var int64_t var_30h @ rbp-0x30
│           ; var int64_t var_28h @ rbp-0x28
│           ; var int64_t var_20h @ rbp-0x20
│           ; var int64_t var_18h @ rbp-0x18
│           ; var int64_t var_16h @ rbp-0x16
│           ; var int64_t var_dh @ rbp-0xd
│           ; var int64_t var_5h @ rbp-0x5
│           ; var int64_t var_1h @ rbp-0x1
│           0x564a4392e185      55             push rbp
│           0x564a4392e186      4889e5         mov rbp, rsp
│           0x564a4392e189      4881ecc00200.  sub rsp, 0x2c0
│           0x564a4392e190      48b84d616465.  movabs rax, 0x207962206564614d ; 'Made by '
│           0x564a4392e19a      488945f3       mov qword [var_dh], rax
│           0x564a4392e19e      c745fb346e6f.  mov dword [var_5h], 0x6e6f6e34 ; '4non'
│           0x564a4392e1a5      c645ff00       mov byte [var_1h], 0
│           0x564a4392e1a9      48b868747470.  movabs rax, 0x2f2f3a7370747468 ; 'https://'
│           0x564a4392e1b3      48ba67697468.  movabs rdx, 0x632e627568746967 ; 'github.c'
│           0x564a4392e1bd      488945d0       mov qword [var_30h], rax
│           0x564a4392e1c1      488955d8       mov qword [var_28h], rdx
│           0x564a4392e1c5      48b86f6d2f6e.  movabs rax, 0x69626f306e2f6d6f ; 'om/n0obi'
│           0x564a4392e1cf      488945e0       mov qword [var_20h], rax
│           0x564a4392e1d3      66c745e87434   mov word [var_18h], 0x3474 ; 't4'
│           0x564a4392e1d9      c645ea00       mov byte [var_16h], 0
│           0x564a4392e1dd      48b841474236.  movabs rax, 0x6435736a36424741 ; 'AGB6js5d'
│           0x564a4392e1e7      488985c2fdff.  mov qword [var_23eh], rax
│           0x564a4392e1ee      c785cafdffff.  mov dword [var_236h], 0x476b6439 ; '9dkG'
│           0x564a4392e1f8      66c785cefdff.  mov word [var_232h], 0x37 ; '7' ; 55
│           0x564a4392e201      488d3dfc0d00.  lea rdi, str.Insert_your_username:_ ; 0x564a4392f004 ; "Insert your username: "
│           0x564a4392e208      b800000000     mov eax, 0
│           0x564a4392e20d      e83efeffff     call sym.imp.printf     ; int printf(const char *format)
│           0x564a4392e212      488d85d0fdff.  lea rax, [var_230h]
│           0x564a4392e219      4889c6         mov rsi, rax
│           0x564a4392e21c      488d3df80d00.  lea rdi, [0x564a4392f01b] ; "%s"
│           0x564a4392e223      b800000000     mov eax, 0
│           0x564a4392e228      e843feffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│           0x564a4392e22d      488d95d0fdff.  lea rdx, [var_230h]
│           0x564a4392e234      488d8540fdff.  lea rax, [var_2c0h]
│           0x564a4392e23b      4889d6         mov rsi, rdx
│           0x564a4392e23e      4889c7         mov rdi, rax
│           0x564a4392e241      e8eafdffff     call sym.imp.strcpy     ; char *strcpy(char *dest, const char *src)
│           0x564a4392e246      488d95c2fdff.  lea rdx, [var_23eh]
│           0x564a4392e24d      488d8540fdff.  lea rax, [var_2c0h]
│           0x564a4392e254      4889d6         mov rsi, rdx
│           0x564a4392e257      4889c7         mov rdi, rax
│           0x564a4392e25a      e801feffff     call sym.imp.strcmp     ; int strcmp(const char *s1, const char *s2)
│           0x564a4392e25f      85c0           test eax, eax
│       ┌─< 0x564a4392e261      750e           jne 0x564a4392e271
│       │   0x564a4392e263      488d3db40d00.  lea rdi, str._nWelcome  ; 0x564a4392f01e ; "\nWelcome"
│       │   0x564a4392e26a      e8d1fdffff     call sym.imp.puts       ; int puts(const char *s)
│      ┌──< 0x564a4392e26f      eb16           jmp 0x564a4392e287
│      │└─> 0x564a4392e271      488d3daf0d00.  lea rdi, str._nAuthentication_Error ; 0x564a4392f027 ; "\nAuthentication Error"
│      │    0x564a4392e278      e8c3fdffff     call sym.imp.puts       ; int puts(const char *s)
│      │    0x564a4392e27d      bf00000000     mov edi, 0
│      │    0x564a4392e282      e8f9fdffff     call sym.imp.exit       ; void exit(int status)
│      │    ; CODE XREF from sym.vuln @ 0x564a4392e26f
│      └──> 0x564a4392e287      c9             leave
└           0x564a4392e288      c3             ret
[0x7f7b77356090]> 
```
Right, this is massive, lets break it down:
```bash
│           ; var int64_t var_2c0h @ rbp-0x2c0
│           ; var int64_t var_23eh @ rbp-0x23e
│           ; var int64_t var_236h @ rbp-0x236
│           ; var int64_t var_232h @ rbp-0x232
│           ; var int64_t var_230h @ rbp-0x230
│           ; var int64_t var_30h @ rbp-0x30
│           ; var int64_t var_28h @ rbp-0x28
│           ; var int64_t var_20h @ rbp-0x20
│           ; var int64_t var_18h @ rbp-0x18
│           ; var int64_t var_16h @ rbp-0x16
│           ; var int64_t var_dh @ rbp-0xd
│           ; var int64_t var_5h @ rbp-0x5
│           ; var int64_t var_1h @ rbp-0x1
```
These are local variables. We can view the state of their memory (at runtime only) by using `px @rbp-ADDRESS` so to view var_2c0h we would do `px @rbp-0x2c0`. 
```bash
│           0x564a4392e185      55             push rbp
│           0x564a4392e186      4889e5         mov rbp, rsp
│           0x564a4392e189      4881ecc00200.  sub rsp, 0x2c0
│           0x564a4392e190      48b84d616465.  movabs rax, 0x207962206564614d ; 'Made by '
│           0x564a4392e19a      488945f3       mov qword [var_dh], rax
│           0x564a4392e19e      c745fb346e6f.  mov dword [var_5h], 0x6e6f6e34 ; '4non'
│           0x564a4392e1a5      c645ff00       mov byte [var_1h], 0
│           0x564a4392e1a9      48b868747470.  movabs rax, 0x2f2f3a7370747468 ; 'https://'
│           0x564a4392e1b3      48ba67697468.  movabs rdx, 0x632e627568746967 ; 'github.c'
│           0x564a4392e1bd      488945d0       mov qword [var_30h], rax
│           0x564a4392e1c1      488955d8       mov qword [var_28h], rdx
│           0x564a4392e1c5      48b86f6d2f6e.  movabs rax, 0x69626f306e2f6d6f ; 'om/n0obi'
│           0x564a4392e1cf      488945e0       mov qword [var_20h], rax
│           0x564a4392e1d3      66c745e87434   mov word [var_18h], 0x3474 ; 't4'
```
The `push rbp` instruction is always at the start. Thats nice, but what about the rest? Well we can skip that, we can see that its a github link (thanks to r2). What next?
```bash
│           0x564a4392e1dd      48b841474236.  movabs rax, 0x6435736a36424741 ; 'AGB6js5d'
│           0x564a4392e1e7      488985c2fdff.  mov qword [var_23eh], rax
│           0x564a4392e1ee      c785cafdffff.  mov dword [var_236h], 0x476b6439 ; '9dkG'
│           0x564a4392e1f8      66c785cefdff.  mov word [var_232h], 0x37 ; '7' ; 55
│           0x564a4392e201      488d3dfc0d00.  lea rdi, str.Insert_your_username:_ ; 0x564a4392f004 ; "Insert your username: "
│           0x564a4392e208      b800000000     mov eax, 0
│           0x564a4392e20d      e83efeffff     call sym.imp.printf     ; int printf(const char *format)
```
This one is important. We can see the `Insert your username: ` prompt with `printf()` being called right after. Alright, and what about the mess behind it? 
```bash
0x564a4392e1dd  48b841474236.  movabs rax, 0x6435736a36424741 ; 'AGB6js5d'
0x564a4392e1e7  488985c2fdff.  mov qword [var_23eh], rax
0x564a4392e1ee  c785cafdffff.  mov dword [var_236h], 0x476b6439 ; '9dkG'
0x564a4392e1f8  66c785cefdff.  mov word [var_232h], 0x37 ; '7' ; 55
```
Its right before the username prompt, so what could be huh? Do you think it could be the answer? ;)

## Different method

The other way to solve this would be to run `ltrace`:
```
root@kali:~/CTFs/TryHackMe/classicpassword# ltrace ./Challenge.Challenge 
printf("Insert your username: ")                                                    = 22
__isoc99_scanf(0x558b2944d01b, 0x7ffc0749c890, 0, 0Insert your username: aweawie
)                                = 1
strcpy(0x7ffc0749c800, "aweawie")                                                   = 0x7ffc0749c800
strcmp("aweawie", "**********")                                                  = 32
puts("\nAuthentication Error"
Authentication Error
)                                                      = 22
exit(0 <no return ...>
+++ exited (status 0) +++
```
And as you can see, it shows us the `strcmp()` call in plaintext. Awesome!
