#include "rsahelper.h"
int encodeBufferForEncryption(char* fileName, char * buf, char* encodedM, int k);
void _encrypt(mpz_t m, mpz_t e, mpz_t c, mpz_t n);
void OS2IP(mpz_t result, char* encodedMessage, int N);
int getOctetValue(char ch);
void EMSA_PKCS_V1_5_ENCODE(char* M, char* EM, int emLen, int sizeM);
void addPsuedoRandomOctets(int N, int * index, char* EM);
char getRandomOctet();
void addBlockTypeToBuffer(int BT, char* EM, int *index);
void displayEncodedBuffer(char* ch, int N);
void addPsuedoRandomOctets(int N, int * index, char* EM);
void OS2IP(mpz_t result, char* encodedMessage, int N);
int getOctetValue(char ch);
void I2OSP(char* enc, int N, mpz_t num);
void writeEncryptedBuffer(char* outfile, char* buf, int N);
int extractFromKey(char* keyfile, int keyType, mpz_t e, mpz_t n);

//encrypts a file named filename
int encrypt(char* infile, char* outfile, char* key, int keyType)
{
		mpz_t e, c, n, integer_msg;
		mpz_init(e);
		mpz_init(c);
		mpz_init(n);
		mpz_init(integer_msg);
		int ret = extractFromKey(key, keyType, n, e);
		if(ret == 1)
		{
				printf("Certificate not parsed properly\n");
				return 1;
		}
		
		srand(time(0));
		ret = 0;
		char* msg = (char*)malloc(MSG_BUF_LEN* sizeof(char));
		memset(msg, 0, MSG_BUF_LEN);
		int num_octets = N_NUM_BITS/8;
		char* encodedM  = (char*)malloc((num_octets-1)*sizeof(char)); 
		memset(encodedM, 0, num_octets-1);
		char* encrypted_buff = (char*)malloc(num_octets*sizeof(char));
		memset(encrypted_buff, 0, num_octets);
		
		//Handle error of long message
		ret = encodeBufferForEncryption(infile, msg, encodedM, num_octets);
		if(ret == 1) return 1;
		
		//displayEncodedBuffer(encodedM, num_octets-1);
		OS2IP(integer_msg, encodedM, num_octets-1);
		mpz_out_str(NULL, 10, integer_msg);
		_encrypt(integer_msg, e, c, n);
		I2OSP(encrypted_buff, num_octets, c);
		writeEncryptedBuffer(outfile, encrypted_buff, num_octets);
}

int extractFromKey(char* keyfile, int keyType, mpz_t e, mpz_t n)
{
		struct tree* root = parse(keyfile);
		if(root == NULL)
			return;
		int n_exists = 0, e_exists = 0;
		if(keyType == PUBLIC_KEY)
		{
			//The extracted key is public key
			if(root->children)
			{
					if(root->children->next)
					{
						if(root->children->next->child)
						{
								if(root->children->next->child->children)
								{
									if(root->children->next->child->children->child)
									{
										if(root->children->next->child->children->child->content)
										{
											mpz_set_str(n, root->children->next->child->children->child->content, 2);
											n_exists = 1;
										}
									}
									
									if(root->children->next->child->children->next)
									{	
										if(root->children->next->child->children->next->child)
										{
											if(root->children->next->child->children->next->child->content)
											{
													mpz_set_str(e, root->children->next->child->children->next->child->content, 2);
													e_exists = 1;
											}
										}
									}
									
								}
						}
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
							if(root->children->next->next->child)
							{
								if(root->children->next->next->child->content)
								{
											mpz_set_str(e, root->children->next->next->child->content, 2);
											e_exists = 1;	
								}
							}
						}
					}
			}
		}
		
		if(!e_exists || !n_exists)
		{
			//failure
			return 1;
		}
		else
		{
			return 0;
		}
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

int encodeBufferForEncryption(char* fileName, char * buf, char* encodedM, int k)
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
			fileLength = fread(buf, sizeof(char), MSG_BUF_LEN, fp);
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
			EMSA_PKCS_V1_5_ENCODE(buf, encodedM, k-1, fileLength);
			return 0;
}


void OS2IP(mpz_t result, char* encodedMessage, int N)
{
	int i = 0 ;
	mpz_t temp, mul;
	mpz_init(temp);
	mpz_init(mul);
	mpz_set_str(temp, "1", 10);
	for(i = N - 1 ; i >=0 ; i --)
	{
		int value = (int)encodedMessage[i];
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

void EMSA_PKCS_V1_5_ENCODE(char* M, char* EM, int emLen, int sizeM)
{
		int index = 0, i;
		int padLengthOctets;
		addBlockTypeToBuffer(2, EM, &index);
		padLengthOctets = emLen - sizeM - 2;
		addPsuedoRandomOctets(padLengthOctets, &index, EM);
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

void displayEncodedBuffer(char* ch, int N)
{
		int i ;
		for(i = 0 ; i < N ; i++)
			printf("%c ", ch[i]);
}

void addPsuedoRandomOctets(int N, int * index, char* EM)
{
	int i;
	for(i = 0 ; i < N ; i ++)
	{
			EM[*index] = getRandomOctet();
			*index = *index + 1;
	}
}

char getRandomOctet()
{
		int i, n=0;
		char ch = 0 ;
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
void addBlockTypeToBuffer(int BT, char* EM, int *index)
{
	char ch;
	ch  = (char)BT;
	EM[*index] = ch;
	*index = *index  + 1;
}


void writeEncryptedBuffer(char* outfile, char* buf, int N)
{
			FILE *fp;
			fp=fopen(outfile, "wb");
			fwrite(buf, sizeof(char), N, fp);
			fclose(fp);
}


void I2OSP(char* enc, int N, mpz_t num)
{
		int i;
		mpz_t rem, base;
		mpz_init(rem);
		mpz_init(base);
		mpz_init_set_si(base, 256L);
		for(i = N - 1; i >=0 ; i --)
		{
				mpz_tdiv_qr(num, rem, num, base);
				enc[i] = (char)mpz_get_ui(rem);
		}
}
