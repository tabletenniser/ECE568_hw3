#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/sha1.h"
#define KEY_LENGTH 64

// function prototype
uint8_t *HMAC(char *, char *);

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
    SHA1_INFO ctx;
    uint8_t *hmac = HMAC(secret_hex, "\x01");
    printf("Key is %s, msg is %s, SHA1=%s\n", secret_hex, "1", hmac);
	return (0);
}

uint8_t *
HMAC(char *key, char *msg){
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

    printf("\nBEFORE XOR - ipad: ");
    i = 0;
    for(; i < KEY_LENGTH; i++){
        printf("%02x", ipad[i]);
    }
    printf("\nBEFORE XOR - opad: ");
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
    uint8_t sha_again[SHA1_DIGEST_LENGTH];
    sha1_init(&ctx_again);
    sha1_update(&ctx_again, tmp, strlen(tmp));
    sha1_final(&ctx_again, sha_again);

    printf("\nFINAL SHA:\n");
    i = 0;
    for(; i < strlen(sha_again); i++){
        printf("%02x", sha_again[i]);
    }
    printf("\n");

    free(tmp);
    return sha_again;
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
