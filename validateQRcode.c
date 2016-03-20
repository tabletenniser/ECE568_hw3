#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "lib/sha1.h"
#define KEY_LENGTH 64

// function prototype
void HMAC(char *, char *, uint8_t *);
void hmac_fcn(unsigned char*, int, unsigned char *, int, uint8_t *);

void longToBytes(long num, unsigned char arr[4])
{
    arr[0]= (int)((num >> 24) & 0xFF);
    arr[1]= (int)((num >> 16) & 0xFF);
    arr[2]= (int)((num >> 8) & 0xFF);
    arr[3]= (int)( num & 0xFF);
}

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
    /* HMAC(secret_hex, counterChar, hmac); */

    // 2) TRUNCATE AND COMPUTE HOTP VALUE
    uint8_t offset = hmac[SHA1_DIGEST_LENGTH-1] & 0xf;
    long bin_code = (hmac[offset] & 0x7f) << 24
        | (hmac[offset+1] & 0xff) << 16
        | (hmac[offset+2] & 0xff) << 8
        | (hmac[offset+3] & 0xff);
    bin_code = bin_code % 1000000;

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


void HMAC(char *key, char *msg, uint8_t* sha_final){
    int key_len = strlen(key);
    assert(key_len <= 64);

    // STEP #1: Set up ipad[] and opad[] to be '5c5c5c...' and '363636...'
    uint8_t ipad [KEY_LENGTH+1];// = 0x36;
    uint8_t opad [KEY_LENGTH+1];// = 0x5c;
    ipad[KEY_LENGTH] = '\0';
    opad[KEY_LENGTH] = '\0';
    memset(&ipad[0], '\x36', KEY_LENGTH);
    memset(&opad[0], '\x5c', KEY_LENGTH);

    int i = 0;
    for(; i < key_len; i++){
        ipad[i] ^= (uint8_t) (key[i]);
        opad[i] ^= (uint8_t) (key[i]);
    }

    // prepare for SHA1
    int key_msg_len = strlen(msg) + KEY_LENGTH;
    uint8_t *tmp = (uint8_t *) malloc(key_msg_len + 1);
    tmp[key_msg_len] = '\0';

    // construct SHA1 argument
    memcpy(tmp, ipad, KEY_LENGTH);
    memcpy(&tmp[KEY_LENGTH], msg, strlen(msg)+1);

    // 1st sha
    SHA1_INFO ctx;
    uint8_t sha[SHA1_DIGEST_LENGTH];
    sha1_init(&ctx);
    sha1_update(&ctx, tmp, key_msg_len);
    sha1_final(&ctx, sha);

    // 2nd sha
    free(tmp);
    tmp = (uint8_t *) calloc(KEY_LENGTH + SHA1_DIGEST_LENGTH + 1, sizeof(uint8_t));
    memcpy(tmp, opad, KEY_LENGTH);

    memcpy(&tmp[KEY_LENGTH], sha, SHA1_DIGEST_LENGTH+1);

    SHA1_INFO ctx_again;
    sha1_init(&ctx_again);
    sha1_update(&ctx_again, tmp, KEY_LENGTH+SHA1_DIGEST_LENGTH);
    sha1_final(&ctx_again, sha_final);

    free(tmp);
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
    /* HMAC(secret_hex, "1", hmac); */
    hmac_fcn(TChar, 8, secret_hex, 20, hmac);

    // 2) TRUNCATE AND COMPUTE HOTP VALUE
    int offset = hmac[19] & 0xf;
    int bin_code = (hmac[offset] & 0x7f) << 24
        | (hmac[offset+1] & 0xff) << 16
        | (hmac[offset+2] & 0xff) << 8
        | (hmac[offset+3] & 0xff);
    bin_code = bin_code % 1000000;

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

	char *	secret_hex = argv[1];
	char *	HOTP_value = argv[2];
	char *	TOTP_value = argv[3];

	assert (strlen(secret_hex) <= 20);
	assert (strlen(HOTP_value) == 6);
	assert (strlen(TOTP_value) == 6);

	printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		HOTP_value,
		validateHOTP(secret_hex, HOTP_value) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
