#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "lib/sha1.h"

static int
validateTOTP(char *secret_hex, char *TOTP_string)
{
	//TODO: implement
	SHA1_INFO ctx;
	uint8_t sha[40];
	sha1_init(&ctx);
	sha1_update(&ctx, secret_hex, strlen(secret_hex));
	sha1_final(&ctx, sha);

	int offset = sha[39] & 0xf;

	int binary =
		((sha[offset] & 0x7f) << 24) |
		((sha[offset + 1] & 0xff) << 16) |
		((sha[offset + 2] & 0xff) << 8) |
		(sha[offset + 3] & 0xff);

	int otp = binary % 1000000;
	printf("totp: %s otp: %d \n", TOTP_string, otp);

	return (0);
}

int main(int argc, char *argv[])
{
	if (argc != 3)
	{
		printf("Usage: %s [secretHex] [TOTP]\n", argv[0]);
		return (-1);
	}

	char *secret_hex = argv[1];
	char *TOTP_value = argv[2];

	assert(strlen(secret_hex) <= 20);
	assert(strlen(TOTP_value) == 6);

	printf("\nSecret (Hex): %s\nTOTP Value: %s (%s)\n\n",
		   secret_hex,
		   TOTP_value,
		   validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return (0);
}
