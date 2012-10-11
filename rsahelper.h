#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <malloc.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <getopt.h>
#include <openssl/md5.h>
#include <openssl/sha.h>


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
#define SHA1_LEN 20
#define TAG_BOOLEAN 1
#define TAG_SEQUENCE 16
#define TAG_BIT_STRING 3
#define TAG_NULL 5
#define TAG_OID 6
#define TAG_SET 17
#define TAG_PRINTABLE_STRING 19
#define TAG_UTF8_STRING 12
#define TAG_IA5_STRING 22
#define TAG_UTC_TIME 23
#define TAG_OCTET_STRING 4

#define MD5_HASH_LEN 20
#define PRIV_KEY_BUF_LEN 10240
#define MSG_BUF_LEN 1024
#define KEY_BUF_LEN 10240
#define CERTI_LEN 10240
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
int decrypt(char* infile, char* outfile, char* key, int keyType, unsigned char* plain_buff, int* size_decrypt_buff);
extern struct tree* parse(char* keyfile);
extern void parse_display(char* keyfile);
extern void _encrypt(mpz_t m, mpz_t e, mpz_t c, mpz_t n);
extern void OS2IP(mpz_t result, unsigned char* encodedMessage, int N);
extern void I2OSP(unsigned char* enc, int N, mpz_t num);
extern int readFileInBuffer(char* fileName, unsigned char * buf);
extern int generateSign(char* inputFile, char* privKeyFile, char* signedFile);
extern int appendLengthToBuffer(int value, int* buf, int *index);
extern void addOID(int *buf, int* index, const char* oid);
extern void encrypt_buff(unsigned char* plain_buf, unsigned char* out_buf, char* keyfile, int keyType, int plain_buf_size, int* size_encrypted);
extern void writeEncryptedBuffer(char* outfile, unsigned char* buf, int N);
extern struct tree* parseFromBuff(unsigned char* buf, int N);
extern int verify(char* signedFile, char* originalFile, char* pubKeyPath);
extern void _parse_display(struct tree* root);
extern void generateSelfSignedCertificate(char* privKeyLocation, char* outCertificate);
extern void displayBuffer(int* buf, int index, int maxIndex);
extern void getOctetString(int *buf, unsigned char* octet_string,  int index, int maxIndex);
extern void addUsualPublicKeyHeaders(int *pubKeyBuf, int* index, int* totalLength);
extern void getOctetString(int *buf, unsigned char* octet_string,  int index, int maxIndex);
extern int generateSignedBuffer(unsigned char* buf, unsigned char* signedBuf, int n, char* privKeyFile, int* size_encrypted);

