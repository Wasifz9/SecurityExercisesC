#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

int main(int argc, char *argv[])
{
	if (argc != 4)
	{
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return (-1);
	}

	char *issuer = argv[1];
	char *accountName = argv[2];
	char *secret_hex = argv[3];

	assert(strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		   issuer, accountName, secret_hex);

	const char *encoded_issuer = urlEncode(issuer);
	const char *encoded_accountName = urlEncode(accountName);

	// Convert secret hex to binary since this is what base32_encode wants
	uint8_t secret_binary[10];
    uint8_t str_len = strlen(secret_hex);

    for (int i = 0; i < (str_len / 2); i++) 
    {
        sscanf(secret_hex + 2*i, "%02x", &secret_binary[i]);
    }	

	// if base32 encode fails it returns -1
	uint8_t res[20];
	int err = base32_encode(secret_binary, 10, res, 20);
	if(err < 0)
	{
		printf("error in encoding hex!\n");
	}
	

	// printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
	// 	   encoded_issuer, encoded_accountName, res);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authentication
	// Ideal URL - otpauth://totp/ACCOUNTNAME?issuer=ISSUER&secret=SECRET&period=30

	char URL[50];

	sprintf(
		URL,
		"otpauth://totp/%s?issuer=%s&secret=%s&period=30",
		encoded_accountName,
		encoded_issuer,
		res);

	displayQRcode(URL);

	return (0);
}
