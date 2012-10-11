#include "rsahelper.h"
char* getMd5HashFromBuffer(char* plain_buff, int N);
void getHashFromBitString(char* bitString, unsigned char* hash, int digest_length);
int verify(char* signedFile, char* originalFile, char* certiPath)
{
	unsigned char* buf = (unsigned char*)malloc(MSG_BUF_LEN * sizeof(unsigned char));
	unsigned char md5hash[MD5_DIGEST_LENGTH];
	int n = readFileInBuffer(originalFile, buf);
	int i = 0;
	MD5(buf, n, md5hash);
	
	unsigned char* plain_buff = (unsigned char*)malloc(MSG_BUF_LEN* sizeof(unsigned char));
	memset(plain_buff, 0, MSG_BUF_LEN);
	int plain_buff_size = 0;
	//printf("Sign: %s Orig: %s Certi: %s", signedFile, originalFile, certiPath);
	decrypt_verify(signedFile, certiPath, plain_buff, &plain_buff_size);
	//decrypt(signedFile, NULL, pubKeyPath, PUBLIC_KEY, plain_buff, &plain_buff_size);
	//writeEncryptedBuffer("out_trace", plain_buff, plain_buff_size);
	char* md5BitSignature = getMd5HashFromBuffer(plain_buff, plain_buff_size);
	if(md5BitSignature)
	{
				unsigned char hash2[MD5_DIGEST_LENGTH];
				getHashFromBitString(md5BitSignature, hash2, MD5_DIGEST_LENGTH);
				for(i = 0 ; i < MD5_DIGEST_LENGTH; i ++)
				{
					if(hash2[i] !=md5hash[i])
					{
							printf("Verification FAILED\n");
							return 0;
					}
				}
				printf("Verified OK\n");
				return 1;
	}
	printf("Verification FAILED\n");
}

char* getMd5HashFromBuffer(char* plain_buff, int N)
{
	struct tree* root = parseFromBuff(plain_buff, N);
	if(root)
	{
		if(root->children)
		{
			if(root->children->next)
			{
					if(root->children->next->child)
					{
							if(root->children->next->child->content)
							{
									return root->children->next->child->content;
							}
					}
			}
		}
	}
	return NULL;
}

void getHashFromBitString(char* bitString, unsigned char* hash, int digest_length)
{
	int i, j = 0;
	for(i = 0 ; i < digest_length ; i++)
	{
				hash[i] = ((bitString[j]-'0')<<7) + ((bitString[j+1]-'0')<<6) + ((bitString[j+2]-'0')<<5) + ((bitString[j+3]-'0') <<4)+
						  ((bitString[j+4]-'0')<<3) + ((bitString[j+5]-'0')<<2) + ((bitString[j+6]-'0')<<1) + bitString[j+7]-'0';
				j+=8;
	}
}
