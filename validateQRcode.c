#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/sha1.h"

// function prototype
uint8_t *HMAC(char *, char *);

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
    SHA1_INFO ctx;
    uint8_t *hmac = HMAC(secret_hex, "1");
    printf("Key is %s, msg is %s, SHA1=%s\n", secret_hex, "1", hmac);
	return (0);
}

uint8_t *
HMAC(char *key, char *msg){
    printf("msg: %s\n", msg);
    int key_len = strlen(key);
    printf("key: %s -l1: %d -l2: %d\n", key, key_len, strlen(key));
    assert(key_len <= 64);

    // set up the pads
    uint8_t ipad [65];// = 0x36;
    uint8_t opad [65];// = 0x5c;
    ipad[64] = '\0';
    opad[64] = '\0';
    memset(&opad[0], '\x36', 64);
    memset(&ipad[0], '\x5c', 64);
    printf("ipad: %s - length:%d\n", ipad, strlen((char*)ipad));
    printf("opad: %s - length:%d\n", opad, strlen((char*)opad));
    int i = 0;

    // xor
    for(; i < key_len; i++){
        printf("key%d: %x\n", i, atoi(&key[i]));
        /* ipad[i] ^= (uint8_t) atoi(&key[i]); */
        /* opad[i] ^= (uint8_t) atoi(&key[i]); */
        ipad[i] ^= (uint8_t) (key[i]);
        opad[i] ^= (uint8_t) (key[i]);
        printf("ipad%d: %x\n", i, ipad[i]);
        printf("opad%d: %x\n", i, opad[i]);
    }

    // prepare for SHA1
    int key_msg_len = strlen(msg) + 64;
    uint8_t *tmp = (uint8_t *) malloc(key_msg_len + 1);
    tmp[key_msg_len] = '\0';

    // construct SHA1 argument
    strcpy(tmp, ipad);
    printf("BEFORE STRCAT() - tmp: %s : length: %d\n", tmp, strlen((char*)tmp));
    strcat(tmp, msg);
    printf("AFTER STRCAT() - tmp: %s : length: %d\n", tmp, strlen((char*)tmp));

    // 1st sha
    SHA1_INFO ctx;
    uint8_t sha[SHA1_DIGEST_LENGTH];
    sha1_init(&ctx);
    sha1_update(&ctx, tmp, key_msg_len);
    sha1_final(&ctx, sha);

    // 2nd sha
    free(tmp);
    tmp = (uint8_t *) calloc(strlen(opad) + strlen(sha) + 1, sizeof(uint8_t));
    strcpy(tmp, opad);

    printf("\npre-sha2: ");
    i = 0;
    for(; i < strlen(tmp); i++){
        printf("%02x", tmp[i]);
    }
    printf("\n");
    printf("\n???sha1: ");
    i = 0;
    int tmp_len = strlen(tmp);
    puts("");
    for(; i < strlen(sha); i++){
        printf("%02x", sha[i]);
        /* tmp[tmp_len + i] = (uint8_t) sha[i]; */
    }
    tmp[tmp_len + i] = sha[i];
    printf("\n");

    strcat(tmp, (char*) &sha[0]);

    printf("\n???pre-sha2: %d\n", strlen(tmp));
    i = 0;
    for(; i < strlen(tmp); i++){
        printf("%02x", (uint8_t) tmp[i]);
    }
    printf("\n");
    printf("\n???pre-sha2: %s\n", (tmp));

    SHA1_INFO ctx_again;
    uint8_t sha_again[SHA1_DIGEST_LENGTH];
    sha1_init(&ctx_again);
    sha1_update(&ctx_again, tmp, strlen(tmp));
    sha1_final(&ctx_again, sha_again);

    printf("sha2: %s - length: %d\n", sha_again, strlen((char*)&sha_again[0]));

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
