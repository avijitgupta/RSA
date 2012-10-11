#include "rsahelper.h"
char getPEMChar(int value);
void _convert(int* derIntArray, unsigned char* base64, int N, int* len_base_64);	
int convert(int type, char* fileName, char* outfile)
{
	unsigned char* derFile = (unsigned char*)malloc(CERTI_LEN * sizeof(unsigned char));
	unsigned char* base64 = (unsigned char*)malloc(CERTI_LEN * sizeof(unsigned char));
	FILE* fp;
	fp=fopen(fileName, "rb");
	FILE* out;
	out = fopen(outfile, "wb");
	int fileLength = fread(derFile, sizeof(unsigned char), CERTI_LEN, fp);
	int count = 0;
	int* derIntArray = (int*) malloc(fileLength * 8 * sizeof(int));
	int i, j;
	for(i = 0 ; i < fileLength ; i ++)
	{
			for(j = 7 ; j >=0 ; j --)
			{
				derIntArray[count] = derFile[i] & (1<<j) ? 1: 0;
				count++; 
			}
	}
	int len_base_64=0;
	_convert(derIntArray, base64, count, &len_base_64);
	
	char* begin_header;
	char* end_header;
	switch(type)
	{
			case CERTI:			begin_header = "-----BEGIN CERTIFICATE-----\n";
								end_header = "-----END CERTIFICATE-----";
								break;
			case PUBLIC_KEY: 	begin_header = "-----BEGIN PUBLIC KEY-----\n";
								end_header = "-----END PUBLIC KEY-----";
								break;
			case PRIVATE_KEY: 	begin_header ="-----BEGIN RSA PRIVATE KEY-----\n";
								end_header = "-----END RSA PRIVATE KEY-----";
			
	}
	fwrite(begin_header, sizeof(char), strlen(begin_header), out);
	for( i = 0 ; i < len_base_64 ; )
	{
			for(j = 0 ; j < 64 && i <len_base_64 ; j ++)
			{
					fputc(base64[i], out);
					i++;
			}
			fputc('\n', out);
	}
	fwrite(end_header, sizeof(char), strlen(end_header), out);

}

void _convert(int* derIntArray, unsigned char* base64, int N, int* len_base_64)
{
	int i = 0,j ;
	int num_bytes = N / 8;
	int ct = 0;
	if(num_bytes%3 == 0)
	{
		for( i = 0 ; i < N ; )
		{
				int value = 0;
				for(j = 0 ; j < 6 ; j ++)
				{
						value = (value << 1) + derIntArray[i];
						i++;
				}
				base64[ct++] = getPEMChar(value);
		}
		
	}
	else
	{
		int numberOfPadBytes = 3 - (num_bytes%3);
		//Padded
		int count = N;
		for( i = N ; i < (N + 8*numberOfPadBytes); i++)
		{
			derIntArray[i] = 0;
			count++;
		}
		//printf("Count %d" , count);
		for( i = 0 ; i < count ; )
		{
					int value = 0;
					if(i<N)
					{
						for(j = 0 ; j < 6 ; j ++)
						{
								value = (value << 1) + derIntArray[i];
								i++;
						}
						base64[ct++] = getPEMChar(value);
					}
					else
					{
							base64[ct++] = '=';
							i+=6;	
					}
		}
	}
	
	*len_base_64 = ct;
	
	return;
	
	
}


char getPEMChar(int value)
{
		if(value<=25)return 'A'+value;
		else if (value<=51) return (value - 26 + 'a');
		else if(value <=61)	return (value - 52 + '0');
		else if (value==62) return '+';
		else return '/';
}
