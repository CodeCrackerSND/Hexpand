#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
//#include <unistd.h> - LINUX ONLY
#include <io.h>
#include <openssl/crypto.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
//#include <arpa/inet.h> - LINUX ONLY
//#include <winsock.h>
#include <winsock2.h>
#include <inttypes.h>
#include "byteorder.h"

#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))

unsigned int strntoul(const char* str, int length, int base) {
	// char buf[length+1];
	unsigned int Converted;
	char *dup_buf = strdup(str);
	dup_buf[length] = '\0';  // mark the end of string
	Converted = strtoul(dup_buf, NULL, base);
	free(dup_buf);
	return Converted;
}

char* sha1_extend(EVP_MD_CTX *mdctx, char* signature, int length) {
	// Variables defintions should come first:
	int length_modulo; 
	int length_bytes;
	int trunc_length;
	int padding;
	SHA512_CTX* conv;
	unsigned char* data;
	unsigned char* h_data;
	int h_data_size;
	int sha_switch;
	int i,j;
	char* output;

	length_modulo = EVP_MD_CTX_block_size(mdctx); // OLD CODE: mdctx->digest->block_size;
	length_bytes = length_modulo/8;
	trunc_length = length%length_modulo;
	padding = ((trunc_length) < (length_modulo-length_bytes))
							? ((length_modulo-length_bytes) - trunc_length)
							: ((2*length_modulo-length_bytes) - trunc_length);
	//unsigned char data[length+padding+length_bytes];
	data = malloc(length+padding+length_bytes);
	memset(data, 'A', length+padding+length_bytes);
	EVP_DigestUpdate(mdctx, data, length+padding+length_bytes);

    	conv = (SHA512_CTX *)(EVP_MD_CTX_md_data(mdctx));
	h_data = (unsigned char *)&conv->h;
	// OLD CODE: h_data = (unsigned char *)((SHA512_CTX *)mdctx->md_data)->h;

	h_data_size = EVP_MD_CTX_size(mdctx); // OLD CODE: (mdctx->digest->md_size);
	sha_switch = length_modulo/16;
	i = 0;
	j = 0;
	while (i < h_data_size) {
		for (j = 0; j < sha_switch; j++) {
			h_data[i+j] = strntoul(signature+2*(i+sha_switch-1-j), 2, 16);
		}
		i+=sha_switch;
	}

	output = malloc((2*(padding+length_bytes)+1)*sizeof(char));
	output[0] = '8';
	output[1] = '0';
	for (i = 1; i < 2*(padding+length_bytes); i++) output[i] = '0';
	if (length_modulo == 128) sprintf(output+2*padding, "%032" PRIx32 , htole64(8*length));
	else sprintf(output+2*padding, "%016" PRIx32 , htole64(8*length));
	output[2*(padding+length_bytes)] = 0;

	return output;
}

char* md5_extend(EVP_MD_CTX *mdctx, char* signature, int length) {
	int length_modulo = EVP_MD_CTX_block_size(mdctx);// OLD CODE mdctx->digest->block_size;
	int length_bytes = length_modulo/8;
	int trunc_length = length&0x3f;
	int padding = ((trunc_length) < (length_modulo-length_bytes))
							? ((length_modulo-length_bytes) - trunc_length)
							: ((2*length_modulo-length_bytes) - trunc_length);
	int i;
	unsigned char* data;
	char* output;
	MD5_CTX* conv;

	//unsigned char data[length+padding+length_bytes];
	data = malloc(length+padding+length_bytes);
	memset(data, 'A', length+padding+length_bytes);
	EVP_DigestUpdate(mdctx, data, length+padding+length_bytes);
	
    	conv = (MD5_CTX *)(EVP_MD_CTX_md_data(mdctx));
	conv->A = htonl(strntoul(signature, 8, 16));
	conv->B = htonl(strntoul(signature+8, 8, 16));
	conv->C = htonl(strntoul(signature+16, 8, 16));
	conv->D = htonl(strntoul(signature+24, 8, 16));

	output = malloc((2*(padding+length_bytes)+1)*sizeof(char));
	output[0] = '8';
	output[1] = '0';
	for (i = 1; i < 2*(padding+length_bytes); i++) output[i] = '0';
	sprintf(output+2*padding, "%016" PRIx64 , htobe64(8*length));
	output[2*(padding+length_bytes)] = 0;
	return output;
}

void *extend_get_funcbyname(const char* str) {
	if (strcmp(str, "md5") == 0) {
		return &md5_extend;
	} else if (strcmp(str, "sha1") == 0) {
		return &sha1_extend;
	} else if (strcmp(str, "sha256") == 0) {
		return &sha1_extend;
	} else if (strcmp(str, "sha512") == 0) {
		return &sha1_extend;
	} else {
		return NULL;
	}
}

int hash_extend(const EVP_MD *md,
				char* (*extend_function)(EVP_MD_CTX *m, char* s, int l),
				char *signature,
				char *message,
				int length,
				unsigned char* digest,
				char** output) {
	EVP_MD_CTX *mdctx;
	unsigned int block_size;
	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	*output = (*extend_function)(mdctx, signature, length);
	EVP_DigestUpdate(mdctx, message, strlen(message));
	EVP_DigestFinal_ex(mdctx, digest, &block_size);
	EVP_MD_CTX_destroy(mdctx);
	return block_size;
}
