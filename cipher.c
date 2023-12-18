#ifndef CIPHER
#define CIPHER

#include <sys/socket.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

typedef char blk[16];

void flip_cipher(blk key, char* plaintext, char* ciphertext) {

     char mask = ~0;
     int len = 16;

     for (int i = 0; i < len; i++)
          ciphertext[i] = plaintext[i] ^ mask;

}


#endif

