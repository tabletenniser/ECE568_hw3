#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

uint8_t hexFromChar(char c)
{
	if(c >= '0' && c <= '9') return c - '0';
	if(c >= 'a' && c <= 'f') return c - 'a' + 10;
	if(c >= 'A' && c <= 'F') return c - 'A' + 10;
	return 255;
}

int main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	const char* issuer = argv[1];
	const char* accountName = argv[2];
	char* pre_secret_hex = argv[3];
    const char* issuerEncoded;
    const char* accountNameEncoded;
    char secret_hex[21];
	uint8_t secret[10];
	char otpauth[200];
    char buf[100];

	assert (strlen(pre_secret_hex) <= 20 && strlen(pre_secret_hex) > 0);

    // Append zeros to the beginning if less than 20 digits
    int idx = strlen(pre_secret_hex) - 1;
    int cp_idx = 19;
    secret_hex[20] = '\0';
    for(; idx >=0; idx--, cp_idx--){
        secret_hex[cp_idx] = pre_secret_hex[idx];
    }
    while(cp_idx >= 0){
        secret_hex[cp_idx] = '0';
        cp_idx--;
    }

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

    // Convert secret to uint8_t*
    int i;
    for (i = 0; i < strlen(secret_hex); i += 2){
        secret[i/2] = (uint8_t) (hexFromChar(secret_hex[i]) * 16 + hexFromChar(secret_hex[i+1]));
    }

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
    // otpauth://hotp/ACCOUNTNAME?issuer=ISSUER&secret=SECRET&counter=1
    // otpauth://totp/ACCOUNTNAME?issuer=ISSUER&secret=SECRET&period=30
    accountNameEncoded = urlEncode(accountName);
    issuerEncoded = urlEncode(issuer);
    int count = base32_encode(secret, strlen(secret_hex)/2, (uint8_t *) &buf[0], 100);

    // Display the HOTP
    sprintf(otpauth, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1", accountNameEncoded, issuerEncoded, buf);
	displayQRcode(otpauth);

    // Display the TOTP
    sprintf(otpauth, "otpauth://totp/%s?issuer=%s&secret=%s&period=30", accountNameEncoded, issuerEncoded, buf);
	displayQRcode(otpauth);

	return (0);
}
