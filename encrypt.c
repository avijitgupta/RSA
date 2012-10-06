#include "rsahelper.h"
int encodeBufferForEncryption(char* fileName, unsigned char * buf, unsigned char* encodedM, int k);
void _encrypt(mpz_t m, mpz_t e, mpz_t c, mpz_t n);
void OS2IP(mpz_t result, unsigned char* encodedMessage, int N);
int getOctetValue(char ch);
void EMSA_PKCS_V1_5_ENCODE(unsigned char* M, unsigned char* EM, int emLen, int sizeM, int BT);
unsigned char getRandomOctet(int BT);
void addBlockTypeToBuffer(int BT, unsigned char* EM, int *index);
void displayEncodedBuffer(unsigned char* ch, int N);
void addPsuedoRandomOctets(int N, int * index, unsigned char* EM, int BT);
void OS2IP(mpz_t result,unsigned char* encodedMessage, int N);
void I2OSP(unsigned char* enc, int N, mpz_t num);
void writeEncryptedBuffer(char* outfile, unsigned char* buf, int N);
int extractFromKey(char* keyfile, int keyType, mpz_t n, mpz_t e);

void encrypt_buff(char* plain_buf, char* out_buf, char* keyfile, int keyType, int plain_buf_size, int* size_encrypted)
{
		mpz_t e, c, n, integer_msg;
		mpz_init(e);
		mpz_init(c);
		mpz_init(n);
		mpz_init(integer_msg);

		int ret = extractFromKey(keyfile, keyType, n, e);
		if(ret == 1)
		{
				printf("Certificate not parsed properly\n");
				return ;
		}
		//mpz_out_str(NULL, 10, n);
		//printf("\n");
		//mpz_out_str(NULL, 10, e);
		//srand(time(0));
		ret = 0;
		int num_octets = N_NUM_BITS/8;
		
		unsigned char* encodedM  = (unsigned char*)malloc((num_octets-1)*sizeof(unsigned char)); 
		memset(encodedM, 0, num_octets-1);
		EMSA_PKCS_V1_5_ENCODE(plain_buf, encodedM, num_octets-1, plain_buf_size, 1);
		
		OS2IP(integer_msg, encodedM, num_octets-1);
		_encrypt(integer_msg, e, c, n);
		I2OSP(out_buf, num_octets, c);
		*size_encrypted = num_octets;
} 

//encrypts a file named filename
int encrypt(char* infile, char* outfile, char* keyfile, int keyType)
{
		mpz_t e, c, n, integer_msg;
		mpz_init(e);
		mpz_init(c);
		mpz_init(n);
		mpz_init(integer_msg);
		
		int ret = extractFromKey(keyfile, keyType, n, e);
		//mpz_out_str(NULL, 10, n);
		
		if(ret == 1)
		{
				printf("Certificate not parsed properly\n");
				return 1;
		}
		
		srand(time(0));
		ret = 0;
		unsigned char* msg = (unsigned char*)malloc(MSG_BUF_LEN* sizeof(unsigned char));
		memset(msg, 0, MSG_BUF_LEN);
		int num_octets = N_NUM_BITS/8;
		unsigned char* encodedM  = (unsigned char*)malloc((num_octets-1)*sizeof(unsigned char)); 
		memset(encodedM, 0, num_octets-1);
		unsigned char* encrypted_buff = (unsigned char*)malloc(num_octets*sizeof(unsigned char));
		memset(encrypted_buff, 0, num_octets);
		
		//Handle error of long message
		ret = encodeBufferForEncryption(infile, msg, encodedM, num_octets);
		if(ret == 1) return 1;
		
		OS2IP(integer_msg, encodedM, num_octets-1);
		_encrypt(integer_msg, e, c, n);
		I2OSP(encrypted_buff, num_octets, c);
		writeEncryptedBuffer(outfile, encrypted_buff, num_octets);
}

int extractFromKey(char* keyfile, int keyType, mpz_t n, mpz_t e)
{
		struct tree* root = parse(keyfile);
		
		if(root == NULL)
			return 1;
		int n_exists = 0, e_exists = 0;
		if(keyType == PUBLIC_KEY)
		{
			if(root->children)
				if(root->children->next)
					if(root->children->next->child)
						if(root->children->next->child->children)
							if(root->children->next->child->children->child)
								if(root->children->next->child->children->child->children)
								{
									if(root->children->next->child->children->child->children->child)
										if(root->children->next->child->children->child->children->child->content)
										{
												mpz_set_str(n, root->children->next->child->children->child->children->child->content, 2);
												n_exists = 1;
										}
										
									if(root->children->next->child->children->child->children->next)
										if(root->children->next->child->children->child->children->next->child)
											if(root->children->next->child->children->child->children->next->child->content)
											{
													mpz_set_str(e, root->children->next->child->children->child->children->next->child->content, 2);
													e_exists = 1;
											}
								}
		}
		else
		{
			//the extracted key is private key
			if(root->children)
			{
					if(root->children->next)
					{
						if(root->children->next->child->content)
						{
									mpz_set_str(n, root->children->next->child->content, 2);
									n_exists = 1;
						}
						
						if(root->children->next->next)
						{
							if(root->children->next->next->next)
							{
								if(root->children->next->next->next->child)
								{
									if(root->children->next->next->next->child->content)
									{
												//we take d from the private key, instead of e and encrypt stuff
												mpz_set_str(e, root->children->next->next->next->child->content, 2);
												e_exists = 1;
									}
								}
							}
						}
					}
			}
		}

		if(!e_exists || !n_exists)
			return 1;
		return 0;

}


void _encrypt(mpz_t m, mpz_t e, mpz_t c, mpz_t n)
{
		mpz_t res;
		mpz_init(res);
		mpz_init_set_si(res , 1L);
		int i;
		for(i = 0 ; i < N_NUM_BITS; i ++)
		{
				if(mpz_tstbit(e, i) == 1)
				{
					mpz_mul(res, res, m);
					mpz_mod(res, res, n);
				}
				mpz_mul(m, m ,m); 
				mpz_mod(m, m , n);
		}
		mpz_init_set(c, res);
}

int encodeBufferForEncryption(char* fileName, unsigned char * buf, unsigned char* encodedM, int k)
{
			
			int fileLength = 0;
			int numOctets = k - 11;
			FILE *fp;
			fp=fopen(fileName, "rb");
			if(fp == NULL)
			{
					printf("File does not exist");
					return 1;
			}
			fileLength = fread(buf, sizeof(unsigned char), MSG_BUF_LEN, fp);
			if(fileLength > numOctets)
			{
				printf("message too long\n");
				fclose(fp);
				return 1;
			}
			if(fileLength == 0)
			{
					printf("Error reading input Data");
					fclose(fp);
					return 1;
			}
			fclose(fp);
			//free this somewhere
			EMSA_PKCS_V1_5_ENCODE(buf, encodedM, k-1, fileLength, 2);
			return 0;
}


void OS2IP(mpz_t result, unsigned char* encodedMessage, int N)
{
	int i = 0 ;
	mpz_t temp, mul;
	mpz_init(temp);
	mpz_init(mul);
	mpz_set_str(temp, "1", 10);
	for(i = N - 1 ; i >=0 ; i --)
	{
		int value = (int)encodedMessage[i];
	//	printf("%d ", value);
		mpz_mul_si(mul, temp, value);
		mpz_add(result, result, mul);
		mpz_mul_si(temp, temp, 256);
	}
}

int getOctetValue(char ch)
{
		if(ch>='0' && ch<='9')return ch - '0';
		else return ch - 'A' + 10;
}

void EMSA_PKCS_V1_5_ENCODE(unsigned char* M, unsigned char* EM, int emLen, int sizeM, int BT)
{
		int index = 0, i;
		int padLengthOctets;
		addBlockTypeToBuffer(BT, EM, &index);
		padLengthOctets = emLen - sizeM - 2;
		addPsuedoRandomOctets(padLengthOctets, &index, EM, BT);
		//Add null octet
		EM[index] = 0;
		index ++;
		// add the message
		
		for(i = 0 ; i < sizeM ; i ++)
		{
			EM[index] = M[i];
			index ++;
		}
		
} 

void displayEncodedBuffer(unsigned char* ch, int N)
{
		int i ;
		for(i = 0 ; i < N ; i++)
			printf("%c ", ch[i]);
}

void addPsuedoRandomOctets(int N, int * index, unsigned char* EM, int BT)
{
	int i;
	for(i = 0 ; i < N ; i ++)
	{
			EM[*index] = getRandomOctet(BT);
			*index = *index + 1;
	}
}

unsigned char getRandomOctet(int BT)
{
		if(BT==1)
			return 0xFF;
		int i, n=0;
		unsigned char ch = 0 ;
		while(n==0)
		{
			for(i  = 0 ; i < 8 ; i ++)
			{
					n =  n << 1 | rand()%2;
			}
		}
		ch = (char)n;
		return ch;
}

//adds octet representing type 
void addBlockTypeToBuffer(int BT,unsigned char* EM, int *index)
{
	unsigned char ch;
	ch  = (unsigned char)BT;
	EM[*index] = ch;
	*index = *index  + 1;
}


void writeEncryptedBuffer(char* outfile, unsigned char* buf, int N)
{
			FILE *fp;
			fp=fopen(outfile, "wb");
			fwrite(buf, sizeof(unsigned char), N, fp);
			fclose(fp);
}


void I2OSP(unsigned char* enc, int N, mpz_t num)
{
		int i;
		mpz_t rem, base;
		mpz_init(rem);
		mpz_init(base);
		mpz_init_set_si(base, 256L);
		for(i = N - 1; i >=0 ; i --)
		{
				mpz_tdiv_qr(num, rem, num, base);
				enc[i] = (unsigned char)mpz_get_ui(rem);
		}
}
