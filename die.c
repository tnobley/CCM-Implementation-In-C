#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

void dieWithError(char *s) {
  fputs(s,stderr);
  exit(1);
}

void dieWithSystemError(char *s) {
  perror(s);
  exit(2);
}