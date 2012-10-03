#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <malloc.h>
#include <string.h>
#include "rsahelper.h"

void displayBuffer(int* buf, int index, int maxIndex);
void appendIdentifierOctet(int tag, int type, int class, int* buf, int* index);
int appendLengthToBuffer(int value, int* buf, int *index);
int addMpz_tToBuffer(mpz_t n, int* buf, int* index, int numBits);
void addNullOctet(int* buf, int* index);
void addUsualPublicKeyHeaders(int *pubKeyBuf, int* index, int* totalLength);
void addRsaEncryptionOID(int *pubKeyBuf, int* index, const char* oid);
void writeKeyBuffer(int *buf, int index, int maxIndex, int type);
void writeSampleFile();
void encodeBufferForEncryption(char * buf, char* encodedM, int k);
void EMSA_PKCS_V1_5_ENCODE(char* M, char* EM, int emLen, int sizeM);
void addBlockTypeToBuffer(int BT, char* EM, int *index);
char getRandomOctet();
char findCharacter(int n);
void displayEncodedBuffer(char* ch, int N);
void addPsuedoRandomOctets(int N, int * index, char* EM);
void addEToPublicKeyBuffer(mpz_t e, int* pubKeyBuf, int* index);
void OS2IP(mpz_t result, char* encodedMessage, int N);
int getOctetValue(char ch);
void I2OSP(char* enc, int N, mpz_t num);
void writeEncryptedBuffer(char* buf, int N);
const char* rsaEncryptionObjectIndentifierValue = "2A864886F70D010101";

/*
 * 
	Sample 64 bit certificate - public key
	
	0:d=0  hl=2 l=  36 cons: SEQUENCE          
    2:d=1  hl=2 l=  13 cons: SEQUENCE          
    4:d=2  hl=2 l=   9 prim: OBJECT            :rsaEncryption
   15:d=2  hl=2 l=   0 prim: NULL              
   17:d=1  hl=2 l=  19 prim: BIT STRING        

avijit@avijit:~$ openssl asn1parse -strparse 17 -in 64pub.pem

    0:d=0  hl=2 l=  16 cons: SEQUENCE          
    2:d=1  hl=2 l=   9 prim: INTEGER           :D4797EF0A166D067
   13:d=1  hl=2 l=   3 prim: INTEGER           :010001

 * 
 * 
 * 
 * */


void encrypt(mpz_t m, mpz_t e, mpz_t c, mpz_t n)
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


int applyExtendedEuclid(mpz_t e, mpz_t phi, mpz_t d)
{
	
	mpz_t x, y, z, a, b, c,  div, temp, mul, tx, ty, tz;
	
	if(mpz_even_p(e))	
		return 0;
	
	mpz_init(x);
	mpz_init(y);
	mpz_init(z);
	mpz_init(a);
	mpz_init(b);
	mpz_init(c);
	mpz_init(mul);
	mpz_init(tx);
	mpz_init(ty);
	mpz_init(tz);
	
	mpz_init(div);
	mpz_init(temp);
	
	mpz_init_set_si(a, 1);
	mpz_init_set_si(b, 0);
	mpz_init_set(c, phi);
	mpz_init_set_si(x, 0);
	mpz_init_set_si(y, 1);
	mpz_init_set(z, e);

	do
	{
		mpz_init_set(tx, x);
		mpz_init_set(ty, y);
		mpz_init_set(tz, z);
		#if DEBUG
			printf("\n\n");
			mpz_out_str(NULL, 10, a);
			printf("\n");
			mpz_out_str(NULL, 10, b);
			printf("\n");
			mpz_out_str(NULL, 10, c);
			printf("\n\n");
			mpz_out_str(NULL, 10, x);
			printf("\n");	
			mpz_out_str(NULL, 10, y);
			printf("\n");
			mpz_out_str(NULL, 10, z);
			printf("\n\n");
		#endif
		mpz_tdiv_qr(div, z, c, z);
		mpz_mul(mul, x, div);
		mpz_sub(x, a, mul);
		mpz_mul(mul, y, div);
		mpz_sub(y, b, mul);
		mpz_init_set(a, tx);
		mpz_init_set(b, ty);
		mpz_init_set(c, tz);
		
		
		#if DEBUG
			mpz_out_str(NULL, 10, div);
			printf("\n");
			
			mpz_out_str(NULL, 10, mul);
			printf("\n Sub:");
			
			mpz_out_str(NULL, 10, x);
			printf("\n");
			
			mpz_out_str(NULL, 10, mul);
			printf("\n");
			
			mpz_out_str(NULL, 10, y);
			printf("\n");
			
			mpz_out_str(NULL, 10, a);
			printf("\n");
			mpz_out_str(NULL, 10, b);
			printf("\n");
			mpz_out_str(NULL, 10, c);
			printf("\n\n");
		#endif
	}while(mpz_cmp_si(z, 0L)!=0);	
	
	//LCM not 1
	if(mpz_cmp_si(tz, 1L)!=0)
	{
		return 0;
	}
	else
	{
		mpz_init_set(d, ty);
		return 1;
	}
}

void addEToPublicKeyBuffer(mpz_t e, int* pubKeyBuf, int* index)
{
	int i;
	for(i = 0 ; i <E_NUM_BITS; i++)
	{
			if(mpz_tstbit(e, i) == 1)
				pubKeyBuf[*index] = 1;
			else
				pubKeyBuf[*index] = 0;
			
			*index = *index - 1;
	}
}


int main()
{
	/*TODO: How will the numbers chosen be of "similar bit length" ?
	 */
		mpz_t p, q, n, phi, decp, decq, e, d, c, m, t , m2, res, k, qinverseModP, exponent1, exponent2, integer_msg;
		gmp_randstate_t randomState;
		int isPrimeP = 0, isPrimeQ = 0,  extraOctetAdded, numOctetsAdded = 0,  totalLength = 0, levelLength = 0;
		int* pubKeyBuf = (int*)malloc(PUB_KEY_BUF_LEN* sizeof(int));
		int* privKeyBuf = (int*)malloc(PRIV_KEY_BUF_LEN* sizeof(int));
		int priv_key_ptr = PRIV_KEY_BUF_LEN - 1;
		int pub_key_ptr = PUB_KEY_BUF_LEN - 1;
		int len_e_octets = E_NUM_BITS / 8;
		//initialising random values
		mpz_init(p);
		mpz_init(integer_msg);
		mpz_init(qinverseModP);
		mpz_init(exponent1);
		mpz_init(exponent2);
		mpz_init(k);
		mpz_init(m);
		mpz_init(c);
		mpz_init(res);
		mpz_init(q);
		mpz_init(n);
		mpz_init(t);
		mpz_init(m2);
		mpz_init(decp);
		mpz_init(decq);
		mpz_init(phi);
		mpz_init(e);
		mpz_init(d);
		mpz_init_set_si(e, 65537L);
		mpz_init_set_si(m , 5L);
		mpz_init_set_si(m2 , 5L);
		//seeding random value
		gmp_randinit_default(randomState);
		gmp_randseed_ui(randomState, time(0));
		int foundE = 0;

		while(!foundE)
		{
		//generatnig primes
			do
			{
				mpz_urandomb(p, randomState ,RSA_NUM_BITS);
				isPrimeP = mpz_probab_prime_p(p, 10);
			}
			while(!isPrimeP);
			
			do
			{
				mpz_urandomb(q, randomState ,RSA_NUM_BITS);
				isPrimeQ = mpz_probab_prime_p(q, 10);
			}
			while(!isPrimeQ);
			
			//p*q
			mpz_mul(n , p , q);
			
			//Assures that we have 1024 bit key
			if(mpz_tstbit(n, N_NUM_BITS - 1) == 0) continue;
			#if DEBUG
				mpz_out_str(NULL, 10, p);
				printf("\n");
				mpz_out_str(NULL, 10, q);
				printf("\n");
				mpz_out_str(NULL, 10, n);
				printf("\n");
				mpz_out_str(NULL, 10, decp);
				printf("\n");
				mpz_out_str(NULL, 10, decq);
				printf("\n");
			#endif
			
			//p - 1
			mpz_sub_ui(decp, p, 1);
			
			// q - 1 
			mpz_sub_ui(decq, q, 1);
			
			//Euler's totient function
			mpz_mul(phi, decp, decq);
			
			
			foundE = applyExtendedEuclid(e, phi, d);

			
			#if DEBUG
				mpz_out_str(NULL, 10, e);
				printf("\n");
				mpz_out_str(NULL, 10, d);
				printf("\n");
			#endif
			
			if(mpz_cmp_si(d, 0L) < 0)
			{
				mpz_add(d, phi, d);
			}
		
		}
				#if DEBUG
			printf("Positive D\n");
			mpz_out_str(NULL, 10, d);
			printf("\n");
		#endif
		//encrypt(m, e, c, n);
		
	//	mpz_powm(res, m2 ,e, n);
		
		#if DEBUG
			printf("Cipher1\n");
			mpz_out_str(NULL, 10, c);
			
			printf("Cipher2\n");
			mpz_out_str(NULL, 10, res);
			
			
			printf("\n");
		#endif
	//	mpz_init_set(k, c);
		
		//encrypt(c, d, t, n); 
		
	//	mpz_powm(res, k ,d, n);
		#if DEBUG
			printf("dec\n");
			mpz_out_str(NULL, 10, t);
			printf("\n");
			//printf("dec 2\n");
			//mpz_out_str(NULL, 10, res);
		#endif

		//Adding E
		{
			addEToPublicKeyBuffer(e, pubKeyBuf, &pub_key_ptr);
			totalLength = len_e_octets;
			
			numOctetsAdded = appendLengthToBuffer(len_e_octets, pubKeyBuf, &pub_key_ptr);
			totalLength+= numOctetsAdded;
			
			appendIdentifierOctet(TAG_INT, PRIMITIVE, UNIVERSAL, pubKeyBuf, &pub_key_ptr);
			totalLength++;
			
			extraOctetAdded = addMpz_tToBuffer(n, pubKeyBuf, &pub_key_ptr, N_NUM_BITS);
			totalLength = totalLength + (N_NUM_BITS/8) + extraOctetAdded ;
			
			numOctetsAdded = appendLengthToBuffer( ( (N_NUM_BITS/8) + extraOctetAdded ) , pubKeyBuf, &pub_key_ptr);
			totalLength+= numOctetsAdded;
			
			appendIdentifierOctet(TAG_INT, PRIMITIVE, UNIVERSAL, pubKeyBuf, &pub_key_ptr);
			totalLength++;
			
			numOctetsAdded = appendLengthToBuffer( totalLength , pubKeyBuf, &pub_key_ptr);
			totalLength+= numOctetsAdded;
			
			appendIdentifierOctet(TAG_SEQUENCE, CONSTRUCTED, UNIVERSAL, pubKeyBuf, &pub_key_ptr);
			totalLength++;
			
			//An octet of 00 is added always, since the content always has multiple of 8 bits, so unused bits is 0
			addNullOctet(pubKeyBuf, &pub_key_ptr);
			totalLength++;
			
			numOctetsAdded = appendLengthToBuffer( totalLength , pubKeyBuf, &pub_key_ptr);
			totalLength+= numOctetsAdded;
			
			appendIdentifierOctet(TAG_BIT_STRING, PRIMITIVE, UNIVERSAL, pubKeyBuf, &pub_key_ptr);
			totalLength++;
		
		addUsualPublicKeyHeaders(pubKeyBuf, &pub_key_ptr, &totalLength);
		// The Key is contained within the pubKeyBuf at this stage
		
		writeKeyBuffer(pubKeyBuf, pub_key_ptr +1, PUB_KEY_BUF_LEN, 1);
		
		free(pubKeyBuf);
		}
		
		//printf("Total octets %d", totalLength);
		
		{
				totalLength = 0;
				mpz_invert (qinverseModP, q, p);
				
				//Adding q^-1 mod p
				extraOctetAdded = addMpz_tToBuffer(qinverseModP, privKeyBuf, &priv_key_ptr, RSA_NUM_BITS);
				levelLength = (RSA_NUM_BITS/8) + extraOctetAdded ;
				totalLength+= levelLength;
				numOctetsAdded = appendLengthToBuffer(levelLength, privKeyBuf, &priv_key_ptr);
				totalLength+=numOctetsAdded;
				appendIdentifierOctet(TAG_INT, PRIMITIVE, UNIVERSAL, privKeyBuf, &priv_key_ptr);
				totalLength++;
				
				mpz_mod(exponent1, d, decp);
				mpz_mod(exponent2, d, decq);
				
				//Adding exponent2
				extraOctetAdded = addMpz_tToBuffer(exponent2, privKeyBuf, &priv_key_ptr, RSA_NUM_BITS);
				levelLength = (RSA_NUM_BITS/8) + extraOctetAdded ;
				totalLength+= levelLength;
				
				numOctetsAdded = appendLengthToBuffer(levelLength, privKeyBuf, &priv_key_ptr);
				totalLength+=numOctetsAdded;
				appendIdentifierOctet(TAG_INT, PRIMITIVE, UNIVERSAL, privKeyBuf, &priv_key_ptr);
				totalLength++;
				
				//Adding exponent1
				extraOctetAdded = addMpz_tToBuffer(exponent1, privKeyBuf, &priv_key_ptr, RSA_NUM_BITS);
				levelLength = (RSA_NUM_BITS/8) + extraOctetAdded ;
				totalLength+= levelLength;
				
				numOctetsAdded = appendLengthToBuffer(levelLength, privKeyBuf, &priv_key_ptr);
				totalLength+=numOctetsAdded;
				appendIdentifierOctet(TAG_INT, PRIMITIVE, UNIVERSAL, privKeyBuf, &priv_key_ptr);
				totalLength++;
				
				//Adding prime2
				extraOctetAdded = addMpz_tToBuffer(q, privKeyBuf, &priv_key_ptr, RSA_NUM_BITS);
				levelLength = (RSA_NUM_BITS/8) + extraOctetAdded ;
				totalLength+= levelLength;
				
				numOctetsAdded = appendLengthToBuffer(levelLength, privKeyBuf, &priv_key_ptr);
				totalLength+=numOctetsAdded;
				appendIdentifierOctet(TAG_INT, PRIMITIVE, UNIVERSAL, privKeyBuf, &priv_key_ptr);
				totalLength++;
				
				//Adding prime1
				extraOctetAdded = addMpz_tToBuffer(p, privKeyBuf, &priv_key_ptr, RSA_NUM_BITS);
				levelLength = (RSA_NUM_BITS/8) + extraOctetAdded ;
				totalLength+= levelLength;
				
				numOctetsAdded = appendLengthToBuffer(levelLength, privKeyBuf, &priv_key_ptr);
				totalLength+=numOctetsAdded;
				appendIdentifierOctet(TAG_INT, PRIMITIVE, UNIVERSAL, privKeyBuf, &priv_key_ptr);
				totalLength++;
				
				//Adding d
				extraOctetAdded = addMpz_tToBuffer(d, privKeyBuf, &priv_key_ptr, N_NUM_BITS);
				levelLength = (N_NUM_BITS/8) + extraOctetAdded ;
				totalLength+= levelLength;
				
				numOctetsAdded = appendLengthToBuffer(levelLength, privKeyBuf, &priv_key_ptr);
				totalLength+=numOctetsAdded;
				appendIdentifierOctet(TAG_INT, PRIMITIVE, UNIVERSAL, privKeyBuf, &priv_key_ptr);
				totalLength++;
				
				//Adding e
				extraOctetAdded = addMpz_tToBuffer(e, privKeyBuf, &priv_key_ptr, E_NUM_BITS);
				levelLength = (E_NUM_BITS/8) + extraOctetAdded ;
				totalLength+= levelLength;
				
				numOctetsAdded = appendLengthToBuffer(levelLength, privKeyBuf, &priv_key_ptr);
				totalLength+=numOctetsAdded;
				appendIdentifierOctet(TAG_INT, PRIMITIVE, UNIVERSAL, privKeyBuf, &priv_key_ptr);
				totalLength++;
				
				//Adding n
				extraOctetAdded = addMpz_tToBuffer(n, privKeyBuf, &priv_key_ptr, N_NUM_BITS);
				levelLength = (N_NUM_BITS/8) + extraOctetAdded ;
				totalLength+= levelLength;
				
				numOctetsAdded = appendLengthToBuffer(levelLength, privKeyBuf, &priv_key_ptr);
				totalLength+=numOctetsAdded;
				appendIdentifierOctet(TAG_INT, PRIMITIVE, UNIVERSAL, privKeyBuf, &priv_key_ptr);
				totalLength++;
				
				//Appending version - 0
				addNullOctet(privKeyBuf, &priv_key_ptr);
				totalLength++;
				numOctetsAdded = appendLengthToBuffer(1, privKeyBuf, &priv_key_ptr);
				totalLength+=numOctetsAdded;
				appendIdentifierOctet(TAG_INT, PRIMITIVE, UNIVERSAL, privKeyBuf, &priv_key_ptr);
				totalLength++;
				
				numOctetsAdded = appendLengthToBuffer(totalLength, privKeyBuf, &priv_key_ptr);
				appendIdentifierOctet(TAG_SEQUENCE, CONSTRUCTED, UNIVERSAL, privKeyBuf, &priv_key_ptr);
				
				writeKeyBuffer(privKeyBuf, priv_key_ptr +1, PRIV_KEY_BUF_LEN, 2);

		}
		//writeSampleFile();
		//free this somewhere
		srand(time(0));
		char* msg = (char*)malloc(MSG_BUF_LEN* sizeof(char));
		int num_octets = N_NUM_BITS/8;
		char* encodedM  = (char*)malloc((num_octets-1)*sizeof(char)); 
		char* encrypted_buff = (char*)malloc(num_octets*sizeof(char));
		
		//Handle error of long message
		encodeBufferForEncryption(msg, encodedM, num_octets);
		
		//displayEncodedBuffer(encodedM, num_octets-1);
		OS2IP(integer_msg, encodedM, num_octets-1);
		mpz_out_str(NULL, 10, integer_msg);
		encrypt(integer_msg, e, c, n);
		I2OSP(encrypted_buff, num_octets, c);
		writeEncryptedBuffer(encrypted_buff, num_octets);
		
	//	mpz_powm(res, m2 ,e, n);
		
		#if DEBUG
			printf("Cipher1\n");
			mpz_out_str(NULL, 10, c);
			
			//printf("Cipher2\n");
			//mpz_out_str(NULL, 10, res);
			
			
			printf("\n");
		#endif
	//	mpz_init_set(k, c);
		
	//	encrypt(c, d, t, n); 
		
	//	mpz_powm(res, k ,d, n);
		#if DEBUG
			printf("dec\n");
			mpz_out_str(NULL, 10, t);
			printf("\n");
			//printf("dec 2\n");
			//mpz_out_str(NULL, 10, res);
		#endif
		
		
		
		return 0;
}

void writeEncryptedBuffer(char* buf, int N)
{
			FILE *fp;
			fp=fopen("/home/avijit/projects/RSA/sampleEnc", "wb");
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
				//mpz_out_str(NULL, 10, rem);
				enc[i] = (char)mpz_get_ui(rem);
				//printf(" %d ", enc[i]);
				//mpz_tdiv_q_ui(num, num, 256);
		}
}

void addUsualPublicKeyHeaders(int *pubKeyBuf, int* index, int* totalLength)
{
	int lengthUsualHeader = 0, numOctetsAdded = 0;
	int protoLen = strlen(rsaEncryptionObjectIndentifierValue)/2;
	//adds 00 length of NULL
	addNullOctet(pubKeyBuf, index);
	*totalLength = *totalLength + 1;
	lengthUsualHeader++;
	
	//printf("Total octets 2 %d", *totalLength);
	//Adding identifier octet for NULL -- 05
	appendIdentifierOctet(TAG_NULL, PRIMITIVE, UNIVERSAL, pubKeyBuf, index);
	*totalLength = *totalLength + 1;
	lengthUsualHeader++;
	
	//printf("Total octets 3 %d", *totalLength);
	//This adds 9 octets
	addRsaEncryptionOID(pubKeyBuf, index, rsaEncryptionObjectIndentifierValue);
	//One octet for 2 hex characters
	*totalLength = *(totalLength) + protoLen;
	lengthUsualHeader = lengthUsualHeader + protoLen;
	
	
	//This ideally adds 1 octet - more if length is high
	numOctetsAdded = appendLengthToBuffer( protoLen , pubKeyBuf, index);
	*totalLength= *(totalLength) + numOctetsAdded;
	lengthUsualHeader+= numOctetsAdded;
	
	//The indentifier octet
	appendIdentifierOctet(TAG_OID, PRIMITIVE, UNIVERSAL, pubKeyBuf, index);
	*totalLength = *totalLength + 1;
	lengthUsualHeader++;
	
	numOctetsAdded = appendLengthToBuffer( lengthUsualHeader , pubKeyBuf, index);
	*totalLength= *totalLength + numOctetsAdded;
			
	appendIdentifierOctet(TAG_SEQUENCE, CONSTRUCTED, UNIVERSAL, pubKeyBuf, index);
	*totalLength = *totalLength + 1;
	
	numOctetsAdded = appendLengthToBuffer( *totalLength , pubKeyBuf, index);
	*totalLength= *totalLength + numOctetsAdded;
			
	appendIdentifierOctet(TAG_SEQUENCE, CONSTRUCTED, UNIVERSAL, pubKeyBuf, index);
	*totalLength = *totalLength + 1;
	
	//displayBuffer(pubKeyBuf, *(index) +1, PUB_KEY_BUF_LEN);
	


	
	
}

void addRsaEncryptionOID(int *pubKeyBuf, int* index, const char* oid)
{
	int N = strlen(oid);
	int i, temp, j;
	for(i = N - 1; i >=0 ; i --)
	{
			if(oid[i]>='0' && oid[i]<='9')
			{
				temp = oid[i] - '0';
			}
			else
			{
				temp = oid[i] - 'A' + 10;
			}
			
			for(j = 0 ; j < 4; j ++)
			{
					pubKeyBuf[*index] = temp%2;
					temp = temp/2;
					*index = *index  - 1;
			}
	}
}

void encodeBufferForEncryption(char * buf, char* encodedM, int k)
{
			
			int fileLength, numOctets;
			numOctets = k - 11;
			FILE *fp;
			fp=fopen("/home/avijit/projects/RSA/msg", "rb");
			if(fp == NULL)
			{
					printf("File does not exist");
					return;
			}
			fileLength = fread(buf, sizeof(char), MSG_BUF_LEN, fp);
			if(fileLength > numOctets)
			{
				printf("message too long\n");
				return;
			}
			fclose(fp);
			//free this somewhere
			EMSA_PKCS_V1_5_ENCODE(buf, encodedM, k-1, fileLength);
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
		int value = encodedMessage[i];
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

//returns hexadeciimal character
char findCharacter(int n)
{
		if(n <=9 ) return (char)('0'+n);
		else return (char)('A' + n - 10);
}

void addNullOctet(int* buf, int* index)
{
	int i;
	for(i = 0 ; i < 8 ; i ++)
		{
				buf[*index] = 0;
				*index = *index - 1;
		}
}

//Returns if an extra octet has been added due to the value of n
int addMpz_tToBuffer(mpz_t n, int* buf, int* index, int numBits)
{
	int i, rem = 0;
	for(i = 0 ; i <numBits ; i ++)
	{
			rem = mpz_tstbit(n, i);
			buf[*index] = rem;
			*index = *index - 1;
	}
	//The last bit added was one - add additional octet
	if(rem == 1)
	{
		for(i = 0 ; i < 8 ; i ++)
		{
				buf[*index] = 0;
				*index = *index - 1;
		}
		return 1;
	}
	return 0;
}

//returns number of octets added

int appendLengthToBuffer(int value, int* buf, int *index)
{
		int i, rem, octets = 0, temp;
		//short length type
		if(value<=127)
		{
			for(i =  0 ; i < 8 ; i ++)
			{
				buf[*index] = value%2;
				value = value / 2;
				*index = *index - 1;
			}
			return 1;
		}
		//long length type
		else
		{
			while(value!=0)
			{
					rem = value % 256;
					value = value / 256;
					octets++;
					for( i = 0 ; i < 8 ; i ++)
					{
						buf[*index] = rem%2;
						rem = rem / 2;
						*index = *index - 1;
					}
			}
			
			temp = octets;
			for(i = 0 ; i < 7 ; i ++)
			{
				buf[*index] = temp%2;
				temp/=2;
				*index = *index - 1;
			}
			
			buf[*index] = 1;
			*index = *index - 1;
			
			return octets + 1;
		}
}

void appendIdentifierOctet(int tag, int type, int class, int* buf, int* index)
{
		int i;
		//append 5 bits of tag
		for(i = 0 ; i < TAG_LEN; i ++)
		{
			buf[*index] = tag%2;
			tag = tag/2;
			*index = *index - 1;
		}
		
		//Appending if primitive/constructed
		
		buf[*index] = type;
		*index = *index - 1;
		
		for(i = 0 ; i < CLASS_LEN; i++)
		{
			buf[*index] = class%2;
			class = class/2;
			*index = *index - 1;
		}

}

void displayBuffer(int* buf, int index, int maxIndex)
{
		int i =0 ; 
		for(i = index; i < maxIndex; i ++)
			printf("%d ", buf[i]);
}
void writeSampleFile()
{
		int N = 7, i;
		char arr[N];
		arr[0]='A';
		arr[1]= 'B';
		arr[2] = 'C';
		for(i = 3 ; i < N ; i ++)arr[i] = 0;
		FILE *fp;
		fp=fopen("/home/avijit/projects/RSA/base.txt", "w");
		fwrite(arr, sizeof(char), N, fp);
		fclose(fp);
}
void writeKeyBuffer(int *buf, int index, int maxIndex, int type)
{
		int i , len, j;
		len = (maxIndex - index ) / 8;
		char binaryKey[len];
		for( i = 0 ; i < len ; i ++)
		{
				char ch = 0;
				for( j = 0 ; j < 8 ; j ++)
				{
						ch = ch<<1;
						if(buf[index + 8*i + j] == 1)
						{
								ch = ch | 1;
						}
						
				}
				binaryKey[i] = ch;
		}
		if(type==1)
		{
			FILE *fp;
			fp=fopen("/home/avijit/projects/RSA/pub.der", "wb");
			fwrite(binaryKey, sizeof(char), len, fp);
			fclose(fp);
		}
		else
		{
			FILE *fp;
			fp=fopen("/home/avijit/projects/RSA/priv.der", "wb");
			fwrite(binaryKey, sizeof(char), len, fp);	
			fclose(fp);
		}
}
