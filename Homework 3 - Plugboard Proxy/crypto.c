#include "crypto.h"
#include "pbproxy.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <getopt.h>
#include <netinet/tcp.h>
#include <openssl/aes.h>
#include <openssl/buffer.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/*Reference:
 * https://stackoverflow.com/questions/3141860/aes-ctr-256-encryption-mode-of-operation-on-openssl*/
int init_ctr(struct ctr_state *state, char *iv) {
    state->num = 0;
    memset(state->ecount, 0, 16);

    /* Initialise counter in 'ivec' to 0 */
    memset(state->ivec + 8, 0, 8);

    /* Copy IV into 'ivec' */
    memcpy(state->ivec, iv, 8);
}

int encrypt_text(char *input_data, char *output_data, int n, AES_KEY *aes_key,
                 struct ctr_state *state) {
    int status = -1;
    status = RAND_pseudo_bytes(output_data, 8);
    if (status != 1) {
        fprintf(stdout, "Initial vector generation failed\n");
        fflush(stdout);
        return -1;
    }
    status = init_ctr(state, output_data);
    AES_ctr128_encrypt(input_data, output_data + 8, n, aes_key, state->ivec,
                       state->ecount, &(state->num));
    return 0;
}

int decrypt_text(char *input_text, char *output_text, int n, AES_KEY *aes_key,
                 struct ctr_state *state) {

    int status = -1;
    status = init_ctr(state, input_text);
    AES_ctr128_encrypt(input_text + 8, output_text, n - 8, aes_key, state->ivec,
                       state->ecount, &(state->num));
    return 0;
}