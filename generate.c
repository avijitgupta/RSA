#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <malloc.h>
#include <string.h>
#define N_NUM_BITS 64
#define RSA_NUM_BITS 32
#define E_NUM_BITS 24
#define DEBUG 0
#define PUB_KEY_BUF_LEN 2048
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
void displayBuffer(int* buf, int index, int maxIndex);
void appendIdentifierOctet(int tag, int type, int class, int* buf, int* index);
int appendLengthToBuffer(int value, int* buf, int *index);
int addNToPublicKeyBuffer(mpz_t n, int* buf, int* index);
void addNullOctet(int* buf, int* index);
void addUsualPublicKeyHeaders(int *pubKeyBuf, int* index, int* totalLength);
void addRsaEncryptionOID(int *pubKeyBuf, int* index, const char* oid);
void writePublicKeyBuffer(int *buf, int index, int maxIndex);

const char* rsaEncryptionObjectIndentifierValue = "2A864886F70D010101";
/*
 * 
	Sample 64 bit certificate
	
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
	
	mpz_t x, y, z, a, b, c, lcm, div, temp, mul, tx, ty, tz;
	
	if(mpz_even_p(e))	
		return 0;
	
	mpz_init(x);
	mpz_init(y);
	mpz_init(z);
	mpz_init(a);
	mpz_init(b);
	mpz_init(c);
		
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

int addEToPublicKeyBuffer(mpz_t e, int* pubKeyBuf, int* index)
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
		mpz_t p, q, n, phi, decp, decq, e, d, c, m, t , m2, res, k;
		gmp_randstate_t randomState;
		int isPrimeP = 0, isPrimeQ = 0, i, extraOctetAdded, numOctetsAdded = 0,  totalLength = 0;
		int* pubKeyBuf = (int*)malloc(PUB_KEY_BUF_LEN* sizeof(int));
		int pub_key_ptr = PUB_KEY_BUF_LEN - 1;
		int len_e_octets = E_NUM_BITS / 8;
		//initialising random values
		mpz_init(p);
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
				mpz_setbit(p, RSA_NUM_BITS - 1);
				isPrimeP = mpz_probab_prime_p(p, 10);
			}
			while(!isPrimeP);
			
			do
			{
				mpz_urandomb(q, randomState ,RSA_NUM_BITS);
				mpz_setbit(q, RSA_NUM_BITS - 1);
				isPrimeQ = mpz_probab_prime_p(q, 10);
			}
			while(!isPrimeQ);
			
			//p*q
			mpz_mul(n , p , q);
				
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

			/*while(!foundE)
			{
				mpz_urandomb(e, randomState ,E_NUM_BITS);
				foundE = applyExtendedEuclid(e, phi, d);
			}
			*/
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
		encrypt(m, e, c, n);
		
	//	mpz_powm(res, m2 ,e, n);
		
		#if DEBUG
			printf("Cipher1\n");
			mpz_out_str(NULL, 10, c);
			
			printf("Cipher2\n");
			mpz_out_str(NULL, 10, res);
			
			
			printf("\n");
		#endif
	//	mpz_init_set(k, c);
		
		encrypt(c, d, t, n); 
		
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
			
			extraOctetAdded = addNToPublicKeyBuffer(n, pubKeyBuf, &pub_key_ptr);
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
		}
		
		addUsualPublicKeyHeaders(pubKeyBuf, &pub_key_ptr, &totalLength);
		// The Key is contained within the pubKeyBuf at this stage
		
		
		
		//printf("Total octets %d", totalLength);
		
		return 0;
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
	
	writePublicKeyBuffer(pubKeyBuf, *(index) +1, PUB_KEY_BUF_LEN);
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
int addNToPublicKeyBuffer(mpz_t n, int* buf, int* index)
{
	int i, rem = 0;
	for(i = 0 ; i <N_NUM_BITS ; i ++)
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
		int i;
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

void writePublicKeyBuffer(int *buf, int index, int maxIndex)
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
		FILE *fp;
		fp=fopen("/home/avijit/projects/RSA/pub.der", "wb");
		fwrite(binaryKey, sizeof(char), len, fp);
}
