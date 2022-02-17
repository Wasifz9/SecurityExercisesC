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
	char *encoded_secret_hex = malloc(strlen(secret_hex) * sizeof(char));
	// printf("before encode!\n");
	if (base32_encode(secret_hex, strlen(secret_hex), encoded_secret_hex, 20) < 0)
	{
		printf("error in encoding hex!\n");
	}
	// printf("after encode!\n");
	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		   encoded_issuer, encoded_accountName, encoded_secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authentication
	// Ideal URL - otpauth://totp/ACCOUNTNAME?issuer=ISSUER&secret=SECRET&period=30

	char URL[50];
	// printf("before URL creation\n");
	sprintf(
		URL,
		"otpauth://totp/%s?issuer=%s&secret=%s&period=30",
		encoded_accountName,
		encoded_issuer,
		encoded_secret_hex);

	// printf("after URL creation\n");
	// printf("%s\n", URL);
	displayQRcode(URL);

	return (0);
}
