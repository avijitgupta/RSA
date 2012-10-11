#include "rsahelper.h"
const char* Md5OidValue = "2A864886F70D0205";
void embed_md5_buffer(int* buf, unsigned char* md5buf, int *index, int digest_len);
void getOctetString(int *buf, unsigned char* octet_string,  int index, int maxIndex);
//We only support SHA1 hashing
/*
 * Sample sign file:
 *  0:d=0  hl=2 l=  32 cons: SEQUENCE          
    2:d=1  hl=2 l=  12 cons: SEQUENCE          
    4:d=2  hl=2 l=   8 prim: OBJECT            :md5
   14:d=2  hl=2 l=   0 prim: NULL              
   16:d=1  hl=2 l=  16 prim: OCTET STRING      [HEX DUMP]:967A0A13CB79DD20F61AD3B20EA83B8A

 * 
 */

int generateSignedBuffer(unsigned char* buf, unsigned char* signedBuf, int n, char* privKeyFile, int* size_encrypted)
{
		int* encoded_buf = (int*)malloc(MSG_BUF_LEN * sizeof(int));
		int  len_d_2 = 0;
		unsigned char md5hash[MD5_DIGEST_LENGTH];
		int i, index = MSG_BUF_LEN -1, numOctetsAdded=0, totalLength = 0, octet_string_len = 0, num_octets;
		
		num_octets = N_NUM_BITS/8;
		MD5(buf, n, md5hash);
		int protoLen = strlen(Md5OidValue)/2;
		#ifdef DEBUG3
			printf("MD5 HASH\n");
			for (i = 0; i < MD5_DIGEST_LENGTH; i++) 
			{
				printf("%02x ", md5hash[i]);
			}
			printf("\n");
		#endif
		
		//embed the md5 buffer
		embed_md5_buffer(encoded_buf, md5hash, &index, MD5_DIGEST_LENGTH);
		totalLength+= MD5_DIGEST_LENGTH;
		
		//append the length octet
		numOctetsAdded = appendLengthToBuffer( MD5_DIGEST_LENGTH , encoded_buf, &index);
		totalLength+=numOctetsAdded;
		//append the identifier octet
		appendIdentifierOctet(TAG_OCTET_STRING, PRIMITIVE, 0, encoded_buf, &index);
		totalLength++;
		
		//Add length octet - 0
		numOctetsAdded = appendLengthToBuffer( 0 , encoded_buf, &index);
		totalLength+=numOctetsAdded;
		len_d_2 += numOctetsAdded;
		
		//Add identifier octet
		appendIdentifierOctet(TAG_NULL, PRIMITIVE, UNIVERSAL, encoded_buf, &index);
		totalLength++;
		len_d_2++;
		
		//append the MD5 object identifier value
		addOID(encoded_buf, &index, Md5OidValue);
		totalLength+=protoLen;
		len_d_2+=protoLen;
		
		//add length of the identifier
		numOctetsAdded = appendLengthToBuffer( protoLen , encoded_buf, &index);
		totalLength+=numOctetsAdded;
		len_d_2+=numOctetsAdded;
		
		//add identifier octet
		appendIdentifierOctet(TAG_OID, PRIMITIVE, UNIVERSAL, encoded_buf, &index);
		totalLength++;
		len_d_2++;
		
		//add length octet
		numOctetsAdded = appendLengthToBuffer( len_d_2 , encoded_buf, &index);
		totalLength+=numOctetsAdded;
		
		//add identifier octet
		appendIdentifierOctet(TAG_SEQUENCE, CONSTRUCTED, UNIVERSAL, encoded_buf, &index);
		totalLength++;
		
		//add length octet
		appendLengthToBuffer( totalLength , encoded_buf, &index);
		
		//add identifier octet
		appendIdentifierOctet(TAG_SEQUENCE, CONSTRUCTED, UNIVERSAL, encoded_buf, &index);
		#ifdef DEBUG2
			displayBuffer(encoded_buf, index+1,  MSG_BUF_LEN);
		#endif
		
		octet_string_len = (MSG_BUF_LEN - index - 1)/8;

		unsigned char* octet_string = (unsigned char*)malloc(octet_string_len * sizeof(unsigned char));
		memset(octet_string, 0, octet_string_len);
		
		getOctetString(encoded_buf, octet_string, index+1, MSG_BUF_LEN);
		
		encrypt_buff(octet_string, signedBuf, privKeyFile, PRIVATE_KEY, octet_string_len, size_encrypted);

}

int generateSign(char* inputFile, char* privKeyFile, char* signedFile)
{
		unsigned char* buf = (unsigned char*)malloc(MSG_BUF_LEN*sizeof(unsigned char));
		int* encoded_buf = (int*)malloc(MSG_BUF_LEN * sizeof(int));
		int size_encrypted, len_d_2 = 0;
		unsigned char md5hash[MD5_DIGEST_LENGTH];
		int i, index = MSG_BUF_LEN -1, numOctetsAdded=0, totalLength = 0, octet_string_len = 0, num_octets;
		int n = readFileInBuffer(inputFile, buf);
		num_octets = N_NUM_BITS/8;
		MD5(buf, n, md5hash);
		int protoLen = strlen(Md5OidValue)/2;
		#ifdef DEBUG3
			printf("MD5 HASH\n");
			for (i = 0; i < MD5_DIGEST_LENGTH; i++) 
			{
				printf("%02x ", md5hash[i]);
			}
			printf("\n");
		#endif
		
		//embed the md5 buffer
		embed_md5_buffer(encoded_buf, md5hash, &index, MD5_DIGEST_LENGTH);
		totalLength+= MD5_DIGEST_LENGTH;
		
		//append the length octet
		numOctetsAdded = appendLengthToBuffer( MD5_DIGEST_LENGTH , encoded_buf, &index);
		totalLength+=numOctetsAdded;
		//append the identifier octet
		appendIdentifierOctet(TAG_OCTET_STRING, PRIMITIVE, 0, encoded_buf, &index);
		totalLength++;
		
		//Add length octet - 0
		numOctetsAdded = appendLengthToBuffer( 0 , encoded_buf, &index);
		totalLength+=numOctetsAdded;
		len_d_2 += numOctetsAdded;
		
		//Add identifier octet
		appendIdentifierOctet(TAG_NULL, PRIMITIVE, UNIVERSAL, encoded_buf, &index);
		totalLength++;
		len_d_2++;
		
		//append the MD5 object identifier value
		addOID(encoded_buf, &index, Md5OidValue);
		totalLength+=protoLen;
		len_d_2+=protoLen;
		
		//add length of the identifier
		numOctetsAdded = appendLengthToBuffer( protoLen , encoded_buf, &index);
		totalLength+=numOctetsAdded;
		len_d_2+=numOctetsAdded;
		
		//add identifier octet
		appendIdentifierOctet(TAG_OID, PRIMITIVE, UNIVERSAL, encoded_buf, &index);
		totalLength++;
		len_d_2++;
		
		//add length octet
		numOctetsAdded = appendLengthToBuffer( len_d_2 , encoded_buf, &index);
		totalLength+=numOctetsAdded;
		
		//add identifier octet
		appendIdentifierOctet(TAG_SEQUENCE, CONSTRUCTED, UNIVERSAL, encoded_buf, &index);
		totalLength++;
		
		//add length octet
		appendLengthToBuffer( totalLength , encoded_buf, &index);
		
		//add identifier octet
		appendIdentifierOctet(TAG_SEQUENCE, CONSTRUCTED, UNIVERSAL, encoded_buf, &index);
		#ifdef DEBUG2
			displayBuffer(encoded_buf, index+1,  MSG_BUF_LEN);
		#endif
		
		octet_string_len = (MSG_BUF_LEN - index - 1)/8;

		unsigned char* octet_string = (unsigned char*)malloc(octet_string_len * sizeof(unsigned char));
		memset(octet_string, 0, octet_string_len);
		
		getOctetString(encoded_buf, octet_string, index+1, MSG_BUF_LEN);
		
		unsigned char* encrypted_buff = (unsigned char*)malloc(num_octets*sizeof(unsigned char));
		memset(encrypted_buff, 0, num_octets);
		
		encrypt_buff(octet_string, encrypted_buff, privKeyFile, PRIVATE_KEY, octet_string_len, &size_encrypted);
		writeEncryptedBuffer(signedFile, encrypted_buff, size_encrypted);
	
		//decrypt(signedFile, "decr", "pub.der", PUBLIC_KEY);
		//writeKeyBuffer(signedFile, encoded_buf, index+1, MSG_BUF_LEN);
}

void embed_md5_buffer(int* buf, unsigned char* md5buf, int *index, int digest_len)
{
	int i,j;
	for(j = digest_len - 1 ; j >=0 ; j --)
	{
			for(i = 0 ; i < 8 ; i ++)
			{
				buf[*index] = md5buf[j] & (1<<i)? 1:0;
				*index = *index  -1;
			}
	}
}

void getOctetString(int *buf, unsigned char* octet_string,  int index, int maxIndex)
{
		int i , len, j;
		len = (maxIndex - index ) / 8;
		for( i = 0 ; i < len ; i ++)
		{
				unsigned char ch = 0;
				for( j = 0 ; j < 8 ; j ++)
				{
						ch = ch<<1;
						if(buf[index + 8*i + j] == 1)
						{
								ch = ch | 1;
						}
						
				}
				octet_string[i] = ch;
				//printf("%d ", ch);
		}	
}


