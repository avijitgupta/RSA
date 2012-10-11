#include "rsahelper.h"
int extractInfoFromCerti(char* certiFile, mpz_t n, mpz_t e);
int extractInfoFromKey(char* keyfile, mpz_t n, mpz_t d, int keyType);
//decrypts only using the private keyfile

int decrypt_verify(char* infile, char* certi_path, unsigned char* plain_buff, int* size_decrypt_buff)
{
		mpz_t d, p, n, integer_cipher;
		mpz_init(d);
		mpz_init(p);
		mpz_init(n);
		mpz_init(integer_cipher);
		int i;
		unsigned char* cipher = (unsigned char*)malloc(MSG_BUF_LEN* sizeof(unsigned char));
		memset(cipher, 0, MSG_BUF_LEN);

		int cipherLength = readFileInBuffer(infile, cipher);
		int ret = extractInfoFromCerti(certi_path, n, d);
		if(ret == 1)
		{
			printf("Extraction Failed from Private Key\n");
			return 1;
		}
		int num_octets = mpz_sizeinbase(n, 2)/8;
		if(num_octets != cipherLength)
		{
			printf("decryption error\n");
			return 1;
		}
		
		unsigned char* decrypted_buff = (unsigned char*)malloc((num_octets-1)*sizeof(unsigned char));
		memset(decrypted_buff, 0, num_octets);
		
		OS2IP(integer_cipher, cipher, num_octets);
		if(mpz_cmp(integer_cipher, n) >0)
		{
				printf("ciphertext representation out of range\n");
				return 1;
		}
		//decryption
		_encrypt(integer_cipher, d, p, n);
		I2OSP(decrypted_buff, num_octets - 1, p);
		int ret2 = getDecryptedBuffer(plain_buff, decrypted_buff, num_octets - 1, size_decrypt_buff);
		return ret2;
}


int decrypt(char* infile, char* outfile, char* key, int keyType, unsigned char* plain_buff, int* size_decrypt_buff)
{
		mpz_t d, p, n, integer_cipher;
		mpz_init(d);
		mpz_init(p);
		mpz_init(n);
		mpz_init(integer_cipher);
		int i;
		unsigned char* cipher = (unsigned char*)malloc(MSG_BUF_LEN* sizeof(unsigned char));
		memset(cipher, 0, MSG_BUF_LEN);

		int cipherLength = readFileInBuffer(infile, cipher);
		
		int ret = extractInfoFromKey(key, n, d, keyType);
		if(ret == 1)
		{
			printf("Extraction Failed from Private Key\n");
			return 1;
		}
		int num_octets = mpz_sizeinbase(n, 2)/8;
		if(num_octets != cipherLength)
		{
			printf("decryption error\n");
			return 1;
		}
		
		unsigned char* decrypted_buff = (unsigned char*)malloc((num_octets-1)*sizeof(unsigned char));
		memset(decrypted_buff, 0, num_octets);
		
		OS2IP(integer_cipher, cipher, num_octets);
		if(mpz_cmp(integer_cipher, n) >0)
		{
				printf("ciphertext representation out of range\n");
				return 1;
		}
		//decryption
		_encrypt(integer_cipher, d, p, n);
		I2OSP(decrypted_buff, num_octets - 1, p);
		
		int ret1 = 0, ret2 = 0 ;
		if(outfile!=NULL)
		{
				ret1 = writeDecryptedFile(outfile, decrypted_buff, num_octets - 1);
		}
		if(plain_buff!=NULL)
		{
				ret2 = getDecryptedBuffer(plain_buff, decrypted_buff, num_octets - 1, size_decrypt_buff);
		}
		return ret1 || ret2;
}

int getDecryptedBuffer(unsigned char* plain_buff, unsigned char* decrypted_buff, int N, int* dec_size)
{
		char * ptr = decrypted_buff;
		int padLen = 0;
		int size = N;
		int i = 0;
		while(*ptr && padLen < N)
		{
			padLen++;
			ptr++;
			size --;
		}
		if(padLen <10)
		{
			printf("decoding error\n");
			return 1;
		}
		if(*ptr == 0)
		{
			//The first plaintext alphabet after null octet
			ptr++;
			//removing null octet from size
			size --;
			for( i = 0 ; i < size; i ++)
			{
					plain_buff[i] = ptr[i];
			}
			*dec_size = size;
			return 0;
		}
		return 1;
}


int extractInfoFromKey(char* keyfile, mpz_t n, mpz_t d, int keyType)
{
		struct tree* root = parse(keyfile);
		
		if(root == NULL)
			return 1;
		if(keyType == PRIVATE_KEY)
		{
			mpz_set_str(n, root->children->next->child->content, 2);
			mpz_set_str(d, root->children->next->next->next->child->content, 2);
		}
		if(keyType == PUBLIC_KEY)
		{
			mpz_set_str(n, root->children->next->child->children->child->children->child->content, 2);
			mpz_set_str(d, root->children->next->child->children->child->children->next->child->content, 2);
		}
}

int extractInfoFromCerti(char* certiFile, mpz_t n, mpz_t e)
{
		struct tree* root = parse(certiFile);
		
		#ifdef DEBUG1
			printf("%s ", root->children->child->children->next->next->next->next->next->next->next->child->children->next->child->children->child->children->child->content);
			printf("%s ", root->children->child->children->next->next->next->next->next->next->next->child->children->next->child->children->child->children->next->child->content);
		#endif
		mpz_set_str(n, root->children->child->children->next->next->next->next->next->next->next->child->children->next->child->children->child->children->child->content, 2);
		mpz_set_str(e, root->children->child->children->next->next->next->next->next->next->next->child->children->next->child->children->child->children->next->child->content, 2);
		
}

int readFileInBuffer(char* fileName, unsigned char * buf)
{
			int fileLength = 0;
			FILE *fp;
			fp=fopen(fileName, "rb");
			if(fp == NULL)
			{
					printf("File does not exist");
					return 0;
			}
			fileLength = fread(buf, sizeof(unsigned char), MSG_BUF_LEN, fp);
			if(fileLength == 0)
			{
					printf("Error reading input Data");
					fclose(fp);
					return 0;
			}
			fclose(fp);
			return fileLength;
}

int writeDecryptedFile(char* fileName, char* buf, int N)
{
		char * ptr = buf;
		int padLen = 0;
		int size = N;
		while(*ptr && padLen < N)
		{
			padLen++;
			ptr++;
			size --;
		}
		if(padLen <10)
		{
			printf("decoding error\n");
			return 1;
		}
		if(*ptr == 0)
		{
			//The first plaintext alphabet after null octet
			ptr++;
			//removing null octet from size
			size --;
			
			FILE *fp;
			fp=fopen(fileName, "wb");
			fwrite(ptr, sizeof(char), size, fp);
			fclose(fp);
			
			return 0;
		}
		return 1;
}
