#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <time.h>

#include "lib/sha1.h"

#define TIME_STEP 30

static int
validateTOTP(char *secret_hex, char *TOTP_string)
{
	// TOTP is basically HTOP with the counter value being time
	// The time value is calculated as: (T-To)/X where x is time step(=30s)
	// and To is initial time value(=0)
	time_t t = time(NULL);
    long counter = t / TIME_STEP;

	// convert counter to binary
	uint8_t c[8];
	for(int i = 7; i >= 0; --i){
		c[i] = counter & 0xff;
		counter >>= 8;
	}

    // convert secret hex string to binary
	uint8_t k[10];
    uint8_t str_len = strlen(secret_hex);

    for (int i = 0; i < (str_len / 2); i++) 
    {
        sscanf(secret_hex + 2*i, "%02x", &k[i]);
    }

	// HMAC - H(K XOR opad, H(K XOR ipad, text))
	// hash is SHA1
	// first do K XORs
	uint8_t outer_k[SHA1_BLOCKSIZE];
	uint8_t inner_k[SHA1_BLOCKSIZE+1];

	bzero( outer_k, sizeof outer_k);
	bzero( inner_k, sizeof inner_k);
	bcopy( k, inner_k, strlen(k));
	bcopy( k, outer_k, strlen(k));

	for(int i = 0; i < SHA1_BLOCKSIZE; ++i){
		outer_k[i] ^= 0x5C;
		inner_k[i] ^= 0x36;
	}

	// do inner hash first
	SHA1_INFO ctx;
	uint8_t inner_hash[SHA1_DIGEST_LENGTH];

	sha1_init(&ctx);
	sha1_update(&ctx, inner_k, SHA1_BLOCKSIZE);
	sha1_update(&ctx, c, 8);
	sha1_final(&ctx, inner_hash);

	// do outter hash next
	uint8_t final_hash[SHA1_DIGEST_LENGTH];

	sha1_init(&ctx);
	sha1_update(&ctx, outer_k, SHA1_BLOCKSIZE);
	sha1_update(&ctx, inner_hash, SHA1_DIGEST_LENGTH);
	sha1_final(&ctx, final_hash);

    // Perform truncate function
	int offset = final_hash[SHA1_DIGEST_LENGTH-1] & 0xf;
	int binary =
		((final_hash[offset] & 0x7f) << 24) |
		((final_hash[offset + 1] & 0xff) << 16) |
		((final_hash[offset + 2] & 0xff) << 8) |
		(final_hash[offset + 3] & 0xff);

    // extract 6 digit number
	int totp = binary % 1000000;
	int input_totp = atoi(TOTP_string);

	printf("totp: %d otp: %d \n", input_totp, totp);

	return (totp == input_totp);
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
