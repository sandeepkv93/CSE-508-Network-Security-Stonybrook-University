#include "pbproxy.h"
#include <openssl/aes.h>
#ifndef CRYPTO_H
#define CRYPTO_H

struct ctr_state {
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned int num;
    unsigned char ecount[AES_BLOCK_SIZE];
};

int encrypt_text(char *input_data, char *output_data,
                 int commandline_argument_count, AES_KEY *session_key,
                 struct ctr_state *state);
int decrypt_text(char *input, char *output, int commandline_argument_count,
                 AES_KEY *session_key, struct ctr_state *state);

#endif