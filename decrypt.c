#include "rsahelper.h"
int extractFromPrivateKey(char* keyfile, mpz_t n, mpz_t d);

//decrypts only using the private keyfile
int decrypt(char* infile, char* outfile, char* key)
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
		
		int ret = extractFromPrivateKey(key, n, d);
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
		//mpz_out_str(NULL, 10, integer_cipher);
		if(mpz_cmp(integer_cipher, n) >0)
		{
				printf("ciphertext representation out of range\n");
				return 1;
		}
		//decryption
		_encrypt(integer_cipher, d, p, n);
		//mpz_out_str(NULL, 10, d);
		I2OSP(decrypted_buff, num_octets - 1, p);
		writeDecryptedFile(outfile, decrypted_buff, num_octets - 1);
//		for(i = 0 ; i < num_octets-1; i ++)
//			printf("%c", decrypted_buff[i]);

}

int extractFromPrivateKey(char* keyfile, mpz_t n, mpz_t d)
{
		struct tree* root = parse(keyfile);
		
		if(root == NULL)
			return 1;
		//int n_octet_len = strlen(root->children->next->child->content) / 8;
		//printf("%d %d", n_octet_len, cipherLength);
		
		mpz_set_str(n, root->children->next->child->content, 2);
		mpz_set_str(d, root->children->next->next->next->child->content, 2);
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
