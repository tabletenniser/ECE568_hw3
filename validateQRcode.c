#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "lib/sha1.h"
#define KEY_LENGTH 64

// function prototype
void hmac_fcn(unsigned char*, int, unsigned char *, int, uint8_t *);

void longToBytes2(long long_num, unsigned char arr[8]){
    int i;
    for (i=7; i>=0; i--){
        arr[i] = long_num & 0xff;
        long_num >>= 8;
    }
}

uint8_t hexFromChar(char c)
{
	if(c >= '0' && c <= '9') return c - '0';
	if(c >= 'a' && c <= 'f') return c - 'a' + 10;
	if(c >= 'A' && c <= 'F') return c - 'A' + 10;
	return 255;
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
    uint8_t hmac[SHA1_DIGEST_LENGTH];
    // 1) COMPUTE HMAC CODE VALUE
    long counter = 1;
    char counterChar[8];
    longToBytes2(counter, counterChar);
    hmac_fcn(counterChar, 8, secret_hex, 20, hmac);

    // 2) TRUNCATE AND COMPUTE HOTP VALUE
    uint8_t offset = hmac[SHA1_DIGEST_LENGTH-1] & 0xf;
    long bin_code = (hmac[offset] & 0x7f) << 24
        | (hmac[offset+1] & 0xff) << 16
        | (hmac[offset+2] & 0xff) << 8
        | (hmac[offset+3] & 0xff);
    bin_code = bin_code % 1000000;


    /************* FOR DEBUG ONLY *************/
    /* printf("\nFINAL HMAC:\n"); */
    /* int i = 0; */
    /* for(; i < SHA1_DIGEST_LENGTH; i++){ */
    /*     printf("%02x", hmac[i]); */
    /* } */
    /* printf("\n"); */
    /* printf("bin_code is: %d\n", bin_code); */

    if (atoi(HOTP_string) == bin_code){
        return 1;
    } else {
        return 0;
    }
}


void hmac_fcn(text, text_len, key, key_len, final_sha)
    unsigned char* text; /* pointer to data stream */
    int text_len; /* length of data stream */
    unsigned char* key; /* pointer to authentication key */
    int key_len; /* length of authentication key */
    uint8_t* final_sha; /* length of authentication key */
{
    SHA1_INFO context;
    unsigned char k_ipad[65]; /* inner padding -
                               * key XORd with ipad
                               *  */
    unsigned char k_opad[65]; /* outer padding -
                               * key XORd with opad
                               *  */
    unsigned char tk[16];
    int i;

	uint8_t key_hex_int[10];
	for (i = 0; i < 10; i++) {
		key_hex_int[i] = ((0xf & (hexFromChar(key[i*2]))) << 4)| (0xf & (hexFromChar(key[i*2+1])));
		/* key_hex_int[i] = ((0xf & (key[i * 2] - '0')) << 4)| (0xf & (key[i * 2 + 1] - '0')); */
    }

    bzero( k_ipad, sizeof k_ipad);
    bzero( k_opad, sizeof k_opad);
    bcopy( key_hex_int, k_ipad, 10);
    bcopy( key_hex_int, k_opad, 10);

    /* XOR key with ipad and opad values */
    for (i=0; i< KEY_LENGTH; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    /*
     *  * perform inner SHA1
     *   */
    /* uint8_t *digest = (uint8_t) malloc(SHA1_DIGEST_LENGTH * sizeof(uint8_t)); */
    uint8_t digest[SHA1_DIGEST_LENGTH];
    sha1_init(&context); /* init context for 1st * pass */
    sha1_update(&context, k_ipad, KEY_LENGTH); /* start with inner pad */
    sha1_update(&context, text, text_len); /* then text of datagram */
    sha1_final(&context, digest); /* finish up 1st pass */

    /*
     *  * perform outer MD5
     *   */
    sha1_init(&context); /* init context for 2nd * pass */
    sha1_update(&context, k_opad, KEY_LENGTH); /* start with outer pad */
    sha1_update(&context, digest, SHA1_DIGEST_LENGTH); /* then results of 1st * hash */
    sha1_final(&context, final_sha); /* finish up 2nd pass */

    return;
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
    uint8_t hmac[SHA1_DIGEST_LENGTH];
    // 1) COMPUTE TIME (msg) FOR HMAC
    time_t cur_time = time(NULL);
    long T = (cur_time- 0) / 30;

    char TChar[8];
    longToBytes2(T, TChar);

    // 2) HMAC COMPUTATION WITH secret_hex and time_val
    hmac_fcn(TChar, 8, secret_hex, 20, hmac);

    // 2) TRUNCATE AND COMPUTE HOTP VALUE
    int offset = hmac[19] & 0xf;
    int bin_code = (hmac[offset] & 0x7f) << 24
        | (hmac[offset+1] & 0xff) << 16
        | (hmac[offset+2] & 0xff) << 8
        | (hmac[offset+3] & 0xff);
    bin_code = bin_code % 1000000;


    /************* FOR DEBUG ONLY *************/
    /* printf("\nFINAL HMAC:\n"); */
    /* int i = 0; */
    /* for(; i < SHA1_DIGEST_LENGTH; i++){ */
    /*     printf("%02x", hmac[i]); */
    /* } */
    /* printf("\n"); */
    /* printf("bin_code is: %d\n", bin_code); */


    if (atoi(TOTP_string) == bin_code){
        return 1;
    } else {
        return 0;
    }
}

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [secretHex] [HOTP] [TOTP]\n", argv[0]);
		return(-1);
	}

	char *	pre_secret_hex = argv[1];
	char *	HOTP_value = argv[2];
	char *	TOTP_value = argv[3];

	assert (strlen(pre_secret_hex) <= 20);
	assert (strlen(HOTP_value) == 6);
	assert (strlen(TOTP_value) == 6);

    // Append zeros to the beginning if less than 20 digits
    char secret_hex[21];
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

	printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		HOTP_value,
		validateHOTP(secret_hex, HOTP_value) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
