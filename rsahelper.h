#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <malloc.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <getopt.h>
#define N_NUM_BITS 1024
#define RSA_NUM_BITS 512
#define E_NUM_BITS 24
#define DEBUG 0
#define PUB_KEY_BUF_LEN 10200
#define TAG_LEN 5
#define CLASS_LEN 2
#define TAG_INT 2
#define PRIMITIVE 0
#define CONSTRUCTED 1
#define UNIVERSAL 0
#define TAG_SEQUENCE 16
#define TAG_BIT_STRING 3
#define TAG_NULL 5
#define TAG_OID 6
#define PRIV_KEY_BUF_LEN 10240
#define MSG_BUF_LEN 1024
#define KEY_BUF_LEN 10240
#define LEN_FILE_NAME 1024
#define PRIVATE_KEY 1
#define PUBLIC_KEY 2

//The ASN1 tree
struct tree
{
		int class;
		int primitive;
		int tag;
		long long length;
		struct LLNode* children; // maintains the start pointer to children llinked list
		char* content;
};

struct LLNode
{
	struct tree* child;
	struct LLNode* next;
};

extern int genrsa(char* priv_out, char* pub_out);
extern int encrypt(char* infile, char* outfile, char* key, int keyType);
extern struct tree* parse(char* keyfile);



