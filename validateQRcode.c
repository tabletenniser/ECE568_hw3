#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/sha1.h"
#define KEY_LENGTH 64

// function prototype
void HMAC(char *, char *, uint8_t *);
void hmac_fcn(unsigned char*, int, unsigned char *, int, uint8_t *);

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
    uint8_t hmac[SHA1_DIGEST_LENGTH];
    // 1) COMPUTE HMAC CODE VALUE
    /* HMAC(secret_hex, "1", hmac); */
    hmac_fcn("1", 1, secret_hex, 20, hmac);
    printf("Key is %s, msg is %s, SHA1=%s\n", secret_hex, "1", hmac);

    printf("\nFINAL HMAC:\n");
    int i = 0;
    for(; i < SHA1_DIGEST_LENGTH; i++){
        printf("%02x", hmac[i]);
    }
    printf("\n");

    // 2) TRUNCATE AND COMPUTE HOTP VALUE
    int offset = hmac[19] & 0xf;
    printf("Offset is: %d\n", offset);
    int bin_code = (hmac[offset] & 0x7f) << 24
        | (hmac[offset+1] & 0xff) << 16
        | (hmac[offset+2] & 0xff) << 8
        | (hmac[offset+3] & 0xff);
    printf("bin_code is: %d\n", (bin_code % 1000000));

	return (0);
}


void hmac_fcn(text, text_len, key, key_len, final_sha)
    unsigned char* text; /* pointer to data stream */
    int text_len; /* length of data stream */
    unsigned char* key; /* pointer to authentication key */
    int key_len; /* length of authentication key */
    uint8_t* final_sha; /* length of authentication key */
{
    printf("text is %s, text_len is %d, key is %s, key_len is %d\n", text, text_len, key, key_len);
    SHA1_INFO context;
    unsigned char k_ipad[65]; /* inner padding -
                               * key XORd with ipad
                               *  */
    unsigned char k_opad[65]; /* outer padding -
                               * key XORd with opad
                               *  */
    unsigned char tk[16];
    int i;
    /* if key is longer than 64 bytes reset it to key=MD5(key) */
    /* if (key_len > 64) { */
    /*     MD5_CTX tctx; */
    /*     MD5Init(&tctx); */
    /*     MD5Update(&tctx, key, key_len); */
    /*     MD5Final(tk, &tctx); */
    /*     key = tk; */
    /*     key_len = 16; */
    /* } */
    /* start out by storing key in pads */
    bzero( k_ipad, sizeof k_ipad);
    bzero( k_opad, sizeof k_opad);
    bcopy( key, k_ipad, key_len);
    bcopy( key, k_opad, key_len);

    /* XOR key with ipad and opad values */
    for (i=0; i< KEY_LENGTH; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    printf("\nBEFORE XOR - ipad: ");
    i = 0;
    for(; i < KEY_LENGTH; i++){
        printf("%02x", k_ipad[i]);
    }
    printf("\nBEFORE XOR - opad: ");
    i = 0;
    for(; i < KEY_LENGTH; i++){
        printf("%02x", k_opad[i]);
    }
    printf("\n");

    /*
     *  * perform inner MD5
     *   */
    /* uint8_t *digest = (uint8_t) malloc(SHA1_DIGEST_LENGTH * sizeof(uint8_t)); */
    uint8_t digest[SHA1_DIGEST_LENGTH];
    sha1_init(&context); /* init context for 1st * pass */
    sha1_update(&context, k_ipad, KEY_LENGTH); /* start with inner pad */
    sha1_update(&context, text, text_len); /* then text of datagram */
    sha1_final(&context, digest); /* finish up 1st pass */

    printf("\nSHA1:\n");
    i = 0;
    for(; i < SHA1_DIGEST_LENGTH; i++){
        printf("%02x", digest[i]);
    }
    printf("\n");

    /*
     *  * perform outer MD5
     *   */
    sha1_init(&context); /* init context for 2nd * pass */
    sha1_update(&context, k_opad, KEY_LENGTH); /* start with outer pad */
    sha1_update(&context, digest, SHA1_DIGEST_LENGTH); /* then results of 1st * hash */
    sha1_final(&context, final_sha); /* finish up 2nd pass */

    printf("\nFINAL SHA:\n");
    i = 0;
    for(; i < SHA1_DIGEST_LENGTH; i++){
        printf("%02x", final_sha[i]);
    }
    printf("\n");

    return;
}


void HMAC(char *key, char *msg, uint8_t* sha_final){
    printf("msg: %s\n", msg);
    int key_len = strlen(key);
    printf("key: %s -l1: %d -l2: %d\n", key, key_len, strlen(key));
    assert(key_len <= 64);

    // STEP #1: Set up ipad[] and opad[] to be '5c5c5c...' and '363636...'
    uint8_t ipad [KEY_LENGTH+1];// = 0x36;
    uint8_t opad [KEY_LENGTH+1];// = 0x5c;
    ipad[KEY_LENGTH] = '\0';
    opad[KEY_LENGTH] = '\0';
    memset(&ipad[0], '\x36', KEY_LENGTH);
    memset(&opad[0], '\x5c', KEY_LENGTH);

    printf("\nBEFORE XOR - ipad: ");
    int i = 0;
    for(; i < KEY_LENGTH; i++){
        printf("%02x", ipad[i]);
    }
    printf("\nBEFORE XOR - opad: ");
    i = 0;
    for(; i < KEY_LENGTH; i++){
        printf("%02x", opad[i]);
    }
    printf("\n");

    i = 0;
    for(; i < key_len; i++){
        ipad[i] ^= (uint8_t) (key[i]);
        opad[i] ^= (uint8_t) (key[i]);
    }

    printf("\nAFTER XOR - ipad: ");
    i = 0;
    for(; i < KEY_LENGTH; i++){
        printf("%02x", ipad[i]);
    }
    printf("\nAFTER XOR - opad: ");
    i = 0;
    for(; i < KEY_LENGTH; i++){
        printf("%02x", opad[i]);
    }
    printf("\n");

    // prepare for SHA1
    int key_msg_len = strlen(msg) + KEY_LENGTH;
    uint8_t *tmp = (uint8_t *) malloc(key_msg_len + 1);
    tmp[key_msg_len] = '\0';

    // construct SHA1 argument
    memcpy(tmp, ipad, KEY_LENGTH);
    printf("\nBEFORE STRCAT() - tmp: ");
    i = 0;
    for(; i < key_msg_len; i++){
        printf("%02x", tmp[i]);
    }
    printf("\n");

    memcpy(&tmp[KEY_LENGTH], msg, strlen(msg)+1);

    printf("\nAFTER STRCAT() - tmp: ");
    i = 0;
    for(; i < key_msg_len; i++){
        printf("%02x", tmp[i]);
    }
    printf("\n");

    // 1st sha
    SHA1_INFO ctx;
    uint8_t sha[SHA1_DIGEST_LENGTH];
    sha1_init(&ctx);
    sha1_update(&ctx, tmp, key_msg_len);
    sha1_final(&ctx, sha);

    printf("\nSHA1:\n");
    i = 0;
    for(; i < SHA1_DIGEST_LENGTH; i++){
        printf("%02x", sha[i]);
    }
    printf("\n");

    // 2nd sha
    free(tmp);
    tmp = (uint8_t *) calloc(KEY_LENGTH + SHA1_DIGEST_LENGTH + 1, sizeof(uint8_t));
    memcpy(tmp, opad, KEY_LENGTH);

    printf("\npre-sha2: ");
    i = 0;
    for(; i < key_msg_len; i++){
        printf("%02x", tmp[i]);
    }
    printf("\n");

    memcpy(&tmp[KEY_LENGTH], sha, SHA1_DIGEST_LENGTH+1);

    printf("\n???pre-sha2: %d\n", KEY_LENGTH+SHA1_DIGEST_LENGTH+1);
    i = 0;
    for(; i < KEY_LENGTH+SHA1_DIGEST_LENGTH+1; i++){
        printf("%02x", tmp[i]);
    }
    printf("\n");

    SHA1_INFO ctx_again;
    sha1_init(&ctx_again);
    sha1_update(&ctx_again, tmp, KEY_LENGTH+SHA1_DIGEST_LENGTH);
    sha1_final(&ctx_again, sha_final);

    printf("\nFINAL SHA:\n");
    i = 0;
    for(; i < SHA1_DIGEST_LENGTH; i++){
        printf("%02x", sha_final[i]);
    }
    printf("\n");

    free(tmp);
    return;
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	return (0);
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
