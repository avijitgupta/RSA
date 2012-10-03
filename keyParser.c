#include "rsahelper.h"

void addNodeToLinkedList(struct tree* parent, struct tree* root);
void nullify(struct tree* root);
struct tree* asn1parse(int* buf, int *start, int maxIndex, int keyBufLen);
void parse_display(struct tree* root);

struct tree* parse(char* keyfile)
{
			int fileLength = 0;
			int* derIntArray;
			int i, j, count = 0;
			unsigned char* derKey = (unsigned char*) malloc(KEY_BUF_LEN*sizeof(unsigned char));
			
			FILE *fp;
			fp=fopen(keyfile, "rb");
			if(fp == NULL)
			{
					printf("File does not exist");
					return NULL;
			}
			fileLength = fread(derKey, sizeof(unsigned char), MSG_BUF_LEN, fp);
			
			derIntArray = (int*) malloc(fileLength * 8 * sizeof(int));
			
			for(i = 0 ; i < fileLength; i ++)
			{
					for(j = 7 ; j >=0 ; j --)
					{
						derIntArray[count] = derKey[i] & (1<<j) ? 1: 0;
						count++; 
					}
			}
			
			int start = 0;
			struct tree* root = asn1parse(derIntArray, &start, count - 1, count);
			//parse(root);
			return root;			
}

//returns 1 if successful, 0 if parse failed
struct tree* asn1parse(int* buf, int *start, int maxIndex, int keyBufLen)
{
	int  i;
	if(*start > maxIndex || *start >= keyBufLen) return NULL;
	
	struct tree* root = (struct tree*) malloc(sizeof(struct tree));
	
	if(root == NULL)
	{
		printf("Problem in memory allocaion");
		return NULL;
	}
	nullify(root);
	
	if(maxIndex - *start + 1 < 8)
	{
		printf("Certificate parse error");
		return NULL;	
	}
	
		//parse the identifier octet
		root->class = (buf[*start]<<1) + (buf[*start + 1]);
		root->primitive = buf[*start+2];
		root->tag = (buf[*start+3]<<4) + (buf[*start+4]<<3) + (buf[*start+5]<<2) + (buf[*start+6]<<1) + buf[*start+7];
		*start +=8;
		// You are currently pointing on the length octet
		int longLength = buf[*start];
		if(!longLength)
		{
				root->length = (buf[*start+1]<<6) + (buf[*start + 2]<<5) + (buf[ *start + 3 ]<<4)  
								+ (buf[ *start + 4]<<3) + (buf[ *start + 5 ]<<2) + (buf[ *start + 6 ]<<1) + (buf[ *start + 7]);
				*start +=8;
		}
		else
		{
			int numLengthOctets = (buf[*start+1]<<6) + (buf[*start + 2]<<5) + (buf[ *start + 3 ]<<4)  
								+ (buf[ *start + 4]<<3) + (buf[ *start + 5 ]<<2) + (buf[*start + 6 ]<<1) + buf[ *start + 7];
			*start+=8;
			//You're now pointing at the first long length startng octet
			long long int len = 0;
			for(i = 0 ; i < numLengthOctets; i++)
			{
					int val = (buf[*start]<<7) +  (buf[*start+1]<<6) + (buf[*start + 2]<<5) + (buf[ *start + 3 ]<<4)  
								+ (buf[ *start + 4]<<3) + (buf[ *start + 5 ]<<2) + (buf[ *start + 6 ]<<1) + buf[ *start + 7];
					len = (len << 8) + val;
					*start+=8;
					if(*start>maxIndex)
					{
						printf("Certificate parse error");
						return NULL;	
					}
			}
			root->length = len;
		}
		//You are currently pointing on the first content octet
		
		//Leaves
		if(root->class == 0 && (root->tag == TAG_INT || root->tag == TAG_OID) )
		{
				//parse integer
				int l = root->length * 8;
				char* content = (char*) malloc((l+1) * sizeof(char));
				for(i = 0 ; i < l ; i ++)
				{
					content[i] = buf[*start] + '0';
					*start = *start + 1;
				}
				content[i]=0;
				
				root->content = content;
				return root;
		}
		else if(root->class == 0 && root->tag == TAG_NULL)
		{
				//parse null
				root->content = NULL;
				return root;
		}
		
		else if(root->class == 0 && (root->tag == TAG_BIT_STRING || root->tag == TAG_SEQUENCE) )
		{
				//parse Bit String
				root->content = NULL;
				while(*start <= maxIndex && *start < keyBufLen )
				{
					struct tree* child;
					if (root->tag == TAG_BIT_STRING)
					{
						//Ignore the null octet
						*start = *start + 8;
					}
					//printf("START %d\n", *start);
					
					child = asn1parse(buf, start, *start + root->length * 8 - 1, keyBufLen);
					addNodeToLinkedList(root, child);
					
				}
				// go back and add more cousins
		}
		
		return root;
	
} 

void addNodeToLinkedList(struct tree* parent, struct tree* root)
{
		if(root == NULL)return;
		struct LLNode* ptr;
		ptr = parent->children;
		struct LLNode* newNode;
		newNode = (struct LLNode*)malloc(sizeof(struct LLNode));
		newNode->child = root;
		newNode->next = NULL;
		if(ptr !=NULL)
		{
			while(ptr->next!=NULL)
			{
				ptr = ptr->next;
			}
			ptr->next = newNode;
		}
		else
		{
				parent->children = newNode;
		}
		return;
}

void parse_display(struct tree* root)
{
		if(root == NULL)return;
		printf("Class: %d Primitive: %d Tag: %d Length: %lld \n", root->class, root->primitive, root->tag, root->length);
		struct LLNode* ptr = root->children;
		while(ptr!=NULL)
		{
			parse_display(ptr->child);
			ptr = ptr->next;
		}
}

void nullify(struct tree* root)
{
		if(root == NULL) return;
		root->class = 0;
		root->primitive = 0;
		root->tag = 0;
		root->length = 0 ;
		root->children = NULL; // No children initially
		root->content = NULL;
}
