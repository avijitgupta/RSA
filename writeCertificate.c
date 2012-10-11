#include "rsahelper.h"
void addCharBuffToCertificate(int* certificateBuffer, char* buf, int N, int* index);
void addBooleanToBuffer(int * buf, int value, int* index);
void addHashToBuffer(int* dest, unsigned char* hash, int*index, int hash_len);
void addPersonalInformation(int* certificateBuffer, int *certificate_ptr, int* totalLength, int* len1, int* len2, int* len3, int* len4, int* len5, int* len6, int* len7);
void addSignAlgorithmHeader(int *certificateBuffer, int* index, int* totalLength);
void addCertificateId(int* dest, unsigned char* hash, int* index, int hash_len);
const char* basicConstraints = "551D13";
const char* AKID = "551D23";
const char* SKID = "551D0E";
const char* EMAIL_OID = "2A864886F70D010901";
const char* CN_OID = "550403";
const char* OUN_OID = "55040B";
const char* LOC_OID = "550407";
const char* ORG_OID = "55040A";
const char* STATE_OID = "550408";
const char* Country_OID = "550406";
const char* md5WithRSAEnc = "2A864886F70D010104";


unsigned char* cert_email_id = "iamfake.new@gmail.com";
unsigned char* dn = "www.facemash.com";
unsigned char* organizationalUnitName = "CS";
unsigned char* localityName = "SB";
unsigned char* orgName = "MS";
unsigned char* state="New york";
unsigned char* country = "US";
unsigned char* valid_start = "121010195514Z";
unsigned char* valid_end = "321010195514Z";
unsigned char* certi_id = "10F25E9854E0E1D6";

/*Generates a DER certificate using information in the private key at
 * location privKey and saves it to the location outCertificate*/
void generateSelfSignedCertificate(char* privKeyLocation, char* outCertificate)
{
	unsigned char* privkey = (unsigned char*) malloc(PRIV_KEY_BUF_LEN * sizeof(unsigned char));
	int n = readFileInBuffer(privKeyLocation, privkey);
	char* N;
	char* e;
	int i, len1 = 0, len2 = 0, len3 = 0, len4 = 0 , len5 = 0, len6=0, len7=0, len_pub = 0;
	int totalLength = 0, numOctetsAdded = 0 ;
	unsigned char pub_key_sha1[SHA1_LEN];
	int len_e_octets = E_NUM_BITS / 8;
	
	int* pub_key = (int*)malloc(PUB_KEY_BUF_LEN*sizeof(int));
	int pub_ptr = PUB_KEY_BUF_LEN - 1;
	
	int* certificateBuffer = (int*) malloc(CERTI_LEN*sizeof(int));
	int certificate_ptr = CERTI_LEN - 1;
	
	//Parse public key in buffer
	struct tree* root = parseFromBuff(privkey, n);
	N = root->children->next->child->content;
	e = root->children->next->next->child->content;
	
	
	addCharBuffToCertificate(pub_key, e , strlen(e), &pub_ptr);
	totalLength = len_e_octets;
	
	numOctetsAdded = appendLengthToBuffer(len_e_octets, pub_key, &pub_ptr);
	totalLength+= numOctetsAdded;
	
	appendIdentifierOctet(TAG_INT, PRIMITIVE, UNIVERSAL, pub_key, &pub_ptr);
	totalLength++;
	
	addCharBuffToCertificate(pub_key, N , strlen(N), &pub_ptr);
	totalLength = totalLength + (strlen(N)/8) ;
	
	numOctetsAdded = appendLengthToBuffer( strlen(N)/8  , pub_key, &pub_ptr);
	totalLength+= numOctetsAdded;
			
	appendIdentifierOctet(TAG_INT, PRIMITIVE, UNIVERSAL, pub_key, &pub_ptr);
	totalLength++;
			
	numOctetsAdded = appendLengthToBuffer( totalLength , pub_key, &pub_ptr);
	totalLength+= numOctetsAdded;
			
	appendIdentifierOctet(TAG_SEQUENCE, CONSTRUCTED, UNIVERSAL, pub_key, &pub_ptr);
	totalLength++;
	
	
	int octet_string_len = (PUB_KEY_BUF_LEN - pub_ptr - 1)/8;

	len_pub = octet_string_len;
	unsigned char* octet_string = (unsigned char*)malloc(octet_string_len * sizeof(unsigned char));
	memset(octet_string, 0, octet_string_len);
		
	getOctetString(pub_key, octet_string, pub_ptr+1, PUB_KEY_BUF_LEN);
	
	//Calculate hash of public key
	SHA1(octet_string, octet_string_len, pub_key_sha1);
	
	#ifdef DEBUG1
		for (i = 0; i < 20; i++) {
			printf("%02x ", pub_key_sha1[i]);
		}
	#endif 
	//displayBuffer(pub_key, pub_ptr+1, PUB_KEY_BUF_LEN);
	//writeKeyBuffer("samplePub", pub_key, pub_ptr + 1, PUB_KEY_BUF_LEN);
	//printf("%s\n%s", N, e);
	///////////////////////////////////////////////////////////////////////////////////////// Calculated Hash of Public Key (for Sub. Key identifier etc)
	
	//Start Certificate generation
	totalLength = 0;
	
	addBooleanToBuffer(certificateBuffer, 255, &certificate_ptr);
	len6++;
	len7++;
	totalLength++;
	numOctetsAdded = appendLengthToBuffer( 1 , certificateBuffer, &certificate_ptr);
	len6+=numOctetsAdded;
	len7+=numOctetsAdded;
	totalLength+=numOctetsAdded;
	appendIdentifierOctet(TAG_BOOLEAN, PRIMITIVE, UNIVERSAL, certificateBuffer, &certificate_ptr);
	totalLength++;
	len6++;
	len7++;
		
	numOctetsAdded = appendLengthToBuffer( len7 , certificateBuffer, &certificate_ptr);
	len6+=numOctetsAdded;
	totalLength+=numOctetsAdded;
	appendIdentifierOctet(TAG_SEQUENCE, CONSTRUCTED, UNIVERSAL, certificateBuffer, &certificate_ptr);
	len6++;
	totalLength++;	
	
	len5 = len6; //initialising level 5 len
	numOctetsAdded = appendLengthToBuffer( len6 , certificateBuffer, &certificate_ptr);
	len5+=numOctetsAdded;
	totalLength+=numOctetsAdded;

	appendIdentifierOctet(TAG_OCTET_STRING, PRIMITIVE, UNIVERSAL, certificateBuffer, &certificate_ptr);
	len5++;
	totalLength++;	

	addOID(certificateBuffer, &certificate_ptr, basicConstraints);
	len5+=strlen(basicConstraints)/2;
	totalLength+=strlen(basicConstraints)/2;
	
	numOctetsAdded = appendLengthToBuffer( strlen(basicConstraints)/2 , certificateBuffer, &certificate_ptr);
	len5+=numOctetsAdded;
	totalLength+=numOctetsAdded;
	
	appendIdentifierOctet(TAG_OID, PRIMITIVE, UNIVERSAL, certificateBuffer, &certificate_ptr);
	len5++;
	totalLength++;	

	len4 = len5;
	numOctetsAdded = appendLengthToBuffer( len5, certificateBuffer, &certificate_ptr);
	len4+= numOctetsAdded;
	totalLength+=numOctetsAdded;
	appendIdentifierOctet(TAG_SEQUENCE, CONSTRUCTED, UNIVERSAL, certificateBuffer, &certificate_ptr);
	len4++;
	totalLength++;
	
	len5 = 0;
	len6 = 0;
	len7 = 0;
	///////// Added Basic Constraints 
	
	addHashToBuffer(certificateBuffer, pub_key_sha1, &certificate_ptr, SHA1_LEN);
	len7+=SHA1_LEN;
	totalLength+=SHA1_LEN;
	
	numOctetsAdded = appendLengthToBuffer( SHA1_LEN, certificateBuffer, &certificate_ptr);
	len7+=numOctetsAdded;
	totalLength+=numOctetsAdded;
	
	//adding cont[0]
	appendIdentifierOctet(0, PRIMITIVE, 2, certificateBuffer, &certificate_ptr);
	len7++;
	totalLength++;
	
	len6 = len7;
	numOctetsAdded = appendLengthToBuffer( len7 , certificateBuffer, &certificate_ptr);
	len6++;
	totalLength++;
	
	appendIdentifierOctet(TAG_SEQUENCE, CONSTRUCTED, UNIVERSAL, certificateBuffer, &certificate_ptr);
	len6++;
	totalLength++;
	
	len5 = len6;
	numOctetsAdded = appendLengthToBuffer( len6, certificateBuffer, &certificate_ptr);
	len5+=numOctetsAdded;
	totalLength +=numOctetsAdded;
	
	appendIdentifierOctet(TAG_OCTET_STRING, PRIMITIVE, UNIVERSAL, certificateBuffer, &certificate_ptr);
	len5++;
	totalLength++;	

	addOID(certificateBuffer, &certificate_ptr, AKID);
	len5+=strlen(AKID)/2;
	totalLength+=strlen(AKID)/2;
	
	numOctetsAdded = appendLengthToBuffer( strlen(AKID)/2 , certificateBuffer, &certificate_ptr);
	len5+=numOctetsAdded;
	totalLength+=numOctetsAdded;
	
	appendIdentifierOctet(TAG_OID, PRIMITIVE, UNIVERSAL, certificateBuffer, &certificate_ptr);
	len5++;
	totalLength++;	

	len4 += len5;
	numOctetsAdded = appendLengthToBuffer( len5, certificateBuffer, &certificate_ptr);
	len4+= numOctetsAdded;
	totalLength+=numOctetsAdded;
	appendIdentifierOctet(TAG_SEQUENCE, CONSTRUCTED, UNIVERSAL, certificateBuffer, &certificate_ptr);
	len4++;
	totalLength++;
	// Added X509v3 Authority Key Identifier

	len5 = 0;
	len6 = 0;
	len7 = 0;
	
	addHashToBuffer(certificateBuffer, pub_key_sha1, &certificate_ptr, SHA1_LEN);
	len6+=SHA1_LEN;
	totalLength+=SHA1_LEN;
	
	numOctetsAdded = appendLengthToBuffer( SHA1_LEN, certificateBuffer, &certificate_ptr);
	len6+=numOctetsAdded;
	totalLength+=numOctetsAdded;

	appendIdentifierOctet(TAG_OCTET_STRING, PRIMITIVE, UNIVERSAL, certificateBuffer, &certificate_ptr);
	len6++;
	totalLength++;
	
	len5 = len6;
	numOctetsAdded = appendLengthToBuffer( len6, certificateBuffer, &certificate_ptr);
	len5+=numOctetsAdded;
	totalLength +=numOctetsAdded;
	
	appendIdentifierOctet(TAG_OCTET_STRING, PRIMITIVE, UNIVERSAL, certificateBuffer, &certificate_ptr);
	len5++;
	totalLength++;	
	
	addOID(certificateBuffer, &certificate_ptr, SKID);
	len5+=strlen(SKID)/2;
	totalLength+=strlen(SKID)/2;
	
	numOctetsAdded = appendLengthToBuffer( strlen(SKID)/2 , certificateBuffer, &certificate_ptr);
	len5+=numOctetsAdded;
	totalLength+=numOctetsAdded;
	
	appendIdentifierOctet(TAG_OID, PRIMITIVE, UNIVERSAL, certificateBuffer, &certificate_ptr);
	len5++;
	totalLength++;	
	
	len4 += len5;
	numOctetsAdded = appendLengthToBuffer( len5, certificateBuffer, &certificate_ptr);
	len4+= numOctetsAdded;
	totalLength+=numOctetsAdded;
	appendIdentifierOctet(TAG_SEQUENCE, CONSTRUCTED, UNIVERSAL, certificateBuffer, &certificate_ptr);
	len4++;
	totalLength++;
	
	// Added X509v3 Subject Key Identifier

	
	len3 = len4;
	numOctetsAdded = appendLengthToBuffer( len4, certificateBuffer, &certificate_ptr);
	len3+= numOctetsAdded;
	totalLength+=numOctetsAdded;
	appendIdentifierOctet(TAG_SEQUENCE, CONSTRUCTED, UNIVERSAL, certificateBuffer, &certificate_ptr);
	len3++;
	totalLength++;
	
	// Added Wrapping Sequence

	len2 = len3;
	numOctetsAdded = appendLengthToBuffer( len3, certificateBuffer, &certificate_ptr);
	len2+=numOctetsAdded;
	totalLength++;
	
	appendIdentifierOctet(3, CONSTRUCTED, 2, certificateBuffer, &certificate_ptr);
	len2++;
	totalLength++;
	
	//// Added cont [3]
	
	for( i = PUB_KEY_BUF_LEN-1 ; i >pub_ptr ; i --)
	{
		certificateBuffer[certificate_ptr--] = pub_key[i];	
	}
	len3 = len_pub ;
	totalLength +=len_pub;
	
	addNullOctet(certificateBuffer, &certificate_ptr);
	len3++;
	totalLength++;
	
	numOctetsAdded = appendLengthToBuffer( len_pub + 1, certificateBuffer, &certificate_ptr);
	len3+=numOctetsAdded;
	totalLength+=numOctetsAdded;
	
	appendIdentifierOctet(TAG_BIT_STRING, PRIMITIVE, UNIVERSAL, certificateBuffer, &certificate_ptr);
	len3++;
	totalLength++;
	
	int temp = len3;
	addUsualPublicKeyHeaders(certificateBuffer, &certificate_ptr, &len3);
	//Extra Info added
	totalLength +=(len3 - temp);
	//Added Public Key

	addPersonalInformation(certificateBuffer, &certificate_ptr, &totalLength, &len1, &len2, &len3, &len4, &len5, &len6, &len7);

	//Added personal info

	len2+=len3;
	numOctetsAdded = appendLengthToBuffer( len3, certificateBuffer, &certificate_ptr);
	len2+=numOctetsAdded;
	totalLength+=numOctetsAdded;
	
	appendIdentifierOctet(TAG_SEQUENCE, CONSTRUCTED, UNIVERSAL, certificateBuffer, &certificate_ptr);
	len3++;
	totalLength++;
	// Sequence wrapper done
	
	addHashToBuffer(certificateBuffer, valid_end, &certificate_ptr, strlen(valid_end));
	
	len5 = strlen(valid_end);
	totalLength+=strlen(valid_end);
	
	numOctetsAdded = appendLengthToBuffer( strlen(valid_end), certificateBuffer, &certificate_ptr);
	len5+=numOctetsAdded;
	totalLength+=numOctetsAdded;
	
	appendIdentifierOctet(TAG_UTC_TIME, PRIMITIVE, UNIVERSAL, certificateBuffer, &certificate_ptr);
	len5++;
	totalLength++;
	
	len4 = len5;
	//UTC end
	
	addHashToBuffer(certificateBuffer, valid_start, &certificate_ptr, strlen(valid_start));
	
	len5 = strlen(valid_start);
	totalLength+=strlen(valid_start);
	
	numOctetsAdded = appendLengthToBuffer( strlen(valid_start), certificateBuffer, &certificate_ptr);
	len5+=numOctetsAdded;
	totalLength+=numOctetsAdded;
	
	appendIdentifierOctet(TAG_UTC_TIME, PRIMITIVE, UNIVERSAL, certificateBuffer, &certificate_ptr);
	len5++;
	totalLength++;
	
	len4 += len5;
	len3 = len4;
	numOctetsAdded = appendLengthToBuffer( len4, certificateBuffer, &certificate_ptr);
	len3+= numOctetsAdded;
	totalLength+=numOctetsAdded;
	appendIdentifierOctet(TAG_SEQUENCE, CONSTRUCTED, UNIVERSAL, certificateBuffer, &certificate_ptr);
	len3++;
	totalLength++;
	
	//Added sequence wrapper for validity
	
	addPersonalInformation(certificateBuffer, &certificate_ptr, &totalLength, &len1, &len2, &len3, &len4, &len5, &len6, &len7);

	//Added personal info

	len2+=len3;
	numOctetsAdded = appendLengthToBuffer( len3, certificateBuffer, &certificate_ptr);
	len2+=numOctetsAdded;
	totalLength+=numOctetsAdded;
	
	appendIdentifierOctet(TAG_SEQUENCE, CONSTRUCTED, UNIVERSAL, certificateBuffer, &certificate_ptr);
	len3++;
	totalLength++;
	// Sequence wrapper done
	
	len3 = 0;
	addSignAlgorithmHeader(certificateBuffer, &certificate_ptr, &len3);
	len2+=len3;
	totalLength+=len3;
	//////// Sign Algorithm Added
	
	addCertificateId(certificateBuffer, certi_id, &certificate_ptr, strlen(certi_id));
	
	len5 = strlen(certi_id)/2;
	totalLength = totalLength + strlen(certi_id)/2;
	
	numOctetsAdded = appendLengthToBuffer( strlen(certi_id)/2, certificateBuffer, &certificate_ptr);
	len5= len5 + numOctetsAdded;
	totalLength = totalLength + numOctetsAdded;
	
	appendIdentifierOctet(TAG_INT, PRIMITIVE, UNIVERSAL, certificateBuffer, &certificate_ptr);
	len5 = len5 + 1;
	totalLength = totalLength + 1;
	///////// added certificate ID
	
	
	addCertificateId(certificateBuffer, "02", &certificate_ptr, 2);
	
	len5 = 1;
	totalLength = totalLength + 1;
	
	numOctetsAdded = appendLengthToBuffer( 1, certificateBuffer, &certificate_ptr);
	len5= len5 + numOctetsAdded;
	totalLength = totalLength + numOctetsAdded;
	
	appendIdentifierOctet(TAG_INT, PRIMITIVE, UNIVERSAL, certificateBuffer, &certificate_ptr);
	len5 = len5 + 1;
	totalLength = totalLength + 1;
	// Added version #
	
	// add cont[3]
	
	numOctetsAdded = appendLengthToBuffer( len5, certificateBuffer, &certificate_ptr);
	totalLength = totalLength + numOctetsAdded;
	
	appendIdentifierOctet(0, PRIMITIVE, 2, certificateBuffer, &certificate_ptr);
	totalLength++;
	
	//sequenceWrapper
	len1 = totalLength;
	numOctetsAdded = appendLengthToBuffer(totalLength, certificateBuffer, &certificate_ptr);
	len3+= numOctetsAdded;
	totalLength+=numOctetsAdded;
	appendIdentifierOctet(TAG_SEQUENCE, CONSTRUCTED, UNIVERSAL, certificateBuffer, &certificate_ptr);
	totalLength++;
	//// generate signature 
	
	//printf("LEN 0 %d ", totalLength);
	int num_octets = N_NUM_BITS/8;
	
	unsigned char* encrypted_buff = (unsigned char*)malloc(num_octets*sizeof(unsigned char));
	
	memset(encrypted_buff, 0, num_octets);
	int size_encrypted = 0;
	octet_string_len = (CERTI_LEN - certificate_ptr - 1)/8;
	
	unsigned char* octet_string2 = (unsigned char*)malloc(octet_string_len * sizeof(unsigned char));
	memset(octet_string2, 0, octet_string_len);
		
	getOctetString(certificateBuffer, octet_string2, certificate_ptr+1, CERTI_LEN);
	
	generateSignedBuffer(octet_string2, encrypted_buff, octet_string_len, privKeyLocation, &size_encrypted);
	
	unsigned int* final_buf = (unsigned int*)malloc(CERTI_LEN*sizeof(unsigned char));
	int index = CERTI_LEN - 1;
	addHashToBuffer(final_buf, encrypted_buff, &index, size_encrypted);
	totalLength += size_encrypted;
	//	printf("LEN 1 %d ", totalLength);

	addNullOctet(final_buf, &index);
	totalLength ++;
	
	numOctetsAdded = appendLengthToBuffer( size_encrypted + 1, final_buf, &index);
	totalLength = totalLength + numOctetsAdded;
	//	printf("LEN 2 %d ", totalLength);

	appendIdentifierOctet(TAG_BIT_STRING, PRIMITIVE, UNIVERSAL, final_buf, &index);
	totalLength++;
	
	len3=0;
	addSignAlgorithmHeader(final_buf, &index, &len3);
	totalLength+=len3;
	//printf("LEN %d ", totalLength);
	//Copy previous buffer
	
	for(i = CERTI_LEN - 1 ; i > certificate_ptr; i --)
	{
			final_buf[index--] = certificateBuffer[i];
	}
	
	numOctetsAdded = appendLengthToBuffer( totalLength, final_buf, &index);
	appendIdentifierOctet(TAG_SEQUENCE, CONSTRUCTED, UNIVERSAL, final_buf, &index);
	
	writeKeyBuffer(outCertificate, final_buf, index + 1, CERTI_LEN);
	
}


void addCharBuffToCertificate(int* dest, char* buf, int N, int* index) 
{
		int i;
		for(i = N - 1 ; i >=0 ; i --)
		{
				dest[*index] = buf[i] - '0';
				*index = *index - 1;
		}
}

void addBooleanToBuffer(int * buf, int value, int* index)
{
		int i;
		for(i = 0 ; i < 8 ; i ++)
		{
				buf[*index] = value%2;
				value/=2;
				*index = *index - 1;
		}
}

void addCertificateId(int* dest, unsigned char* hash, int* index, int hash_len)
{
	int i, j;
	for(i = hash_len - 1 ; i >=0; i --)
	{
			int num;
			if(hash[i]>='0' && hash[i]<='9')
				num = (int)hash[i] - '0';
			else num = (int)hash[i] - 'A' + 10;
			for(j = 0 ; j < 4 ; j++)
			{
					dest[*index] = (num%2);
					
					num/=2;
					*index = *index - 1;
			}
	}
}

void addHashToBuffer(int* dest, unsigned char* hash, int* index, int hash_len)
{
	int i, j;
	for(i = hash_len - 1 ; i >=0; i --)
	{
			int num = (int)hash[i];
			for(j = 0 ; j < 8 ; j++)
			{
					dest[*index] = (num%2);
					num/=2;
					*index = *index - 1;
			}
	}
}

void addPersonalInformation(int* certificateBuffer, int *certificate_ptr, int* totalLength, int* len1, int* len2, int* len3, int* len4, int* len5, int* len6, int* len7)
{
	int numOctetsAdded = 0;
	addHashToBuffer(certificateBuffer, cert_email_id, certificate_ptr, strlen(cert_email_id));
	
	*len5 = strlen(cert_email_id);
	*totalLength = *totalLength + strlen(cert_email_id);
	
	numOctetsAdded = appendLengthToBuffer( strlen(cert_email_id), certificateBuffer, certificate_ptr);
	*len5= *len5 + numOctetsAdded;
	*totalLength = *totalLength + numOctetsAdded;
	
	appendIdentifierOctet(TAG_IA5_STRING, PRIMITIVE, UNIVERSAL, certificateBuffer, certificate_ptr);
	*len5 = *len5 + 1;
	* totalLength = *totalLength + 1;
	
	addOID(certificateBuffer, certificate_ptr, EMAIL_OID);
	*len5= *len5 + strlen(EMAIL_OID)/2;
	* totalLength= *totalLength + strlen(EMAIL_OID)/2;
	
	numOctetsAdded = appendLengthToBuffer( strlen(EMAIL_OID)/2 , certificateBuffer, certificate_ptr);
	*len5= *len5 + numOctetsAdded;
	*totalLength= *totalLength + numOctetsAdded;
	
	appendIdentifierOctet(TAG_OID, PRIMITIVE, UNIVERSAL, certificateBuffer, certificate_ptr);
	*len5 = *len5 + 1;
	* totalLength = *totalLength + 1;
	
	*len4 = *len5;
	numOctetsAdded = appendLengthToBuffer( *len5, certificateBuffer, certificate_ptr);
	*len4 = *len4 + numOctetsAdded;
	*totalLength= *totalLength + numOctetsAdded;
	appendIdentifierOctet(TAG_SEQUENCE, CONSTRUCTED, UNIVERSAL, certificateBuffer, certificate_ptr);
	*len4 = *len4 + 1;
	* totalLength = *totalLength + 1;
	
	*len3 = *len4;
	numOctetsAdded = appendLengthToBuffer( *len4, certificateBuffer, certificate_ptr);
	*len3= *len3 +numOctetsAdded;
	*totalLength= *totalLength + numOctetsAdded;
	appendIdentifierOctet(TAG_SET, CONSTRUCTED, UNIVERSAL, certificateBuffer, certificate_ptr);
	*len3= *len3 +1;
	* totalLength = *totalLength + 1;

	// Added email
	
	
	addHashToBuffer(certificateBuffer, dn, certificate_ptr, strlen(dn));
	
	*len5 = strlen(dn);
	*totalLength= *totalLength + strlen(dn);
	
	numOctetsAdded = appendLengthToBuffer( strlen(dn), certificateBuffer, certificate_ptr);
	*len5= *len5 + numOctetsAdded;
	*totalLength= *totalLength + numOctetsAdded;
	
	appendIdentifierOctet(TAG_UTF8_STRING, PRIMITIVE, UNIVERSAL, certificateBuffer, certificate_ptr);
	*len5= *len5 + 1;
	* totalLength = *totalLength + 1;
	
	addOID(certificateBuffer, certificate_ptr, CN_OID);
	*len5= *len5 + strlen(CN_OID)/2;
	*totalLength= *totalLength + strlen(CN_OID)/2;
	
	numOctetsAdded = appendLengthToBuffer( strlen(CN_OID)/2 , certificateBuffer, certificate_ptr);
	*len5= *len5 + numOctetsAdded;
	*totalLength= *totalLength + numOctetsAdded;
	
	appendIdentifierOctet(TAG_OID, PRIMITIVE, UNIVERSAL, certificateBuffer, certificate_ptr);
	*len5= *len5 + 1;
	* totalLength = *totalLength + 1;
	
	*len4 = *len5;
	numOctetsAdded = appendLengthToBuffer( *len5, certificateBuffer, certificate_ptr);
	*len4 = *len4 + numOctetsAdded;;
	*totalLength= *totalLength + numOctetsAdded;
	appendIdentifierOctet(TAG_SEQUENCE, CONSTRUCTED, UNIVERSAL, certificateBuffer, certificate_ptr);
	*len4 = *len4 + 1;;
	* totalLength = *totalLength + 1;
	
	*len3 = *len3 + *len4;
	numOctetsAdded = appendLengthToBuffer( *len4, certificateBuffer, certificate_ptr);
	*totalLength= *totalLength + numOctetsAdded;
	*len3= *len3 +numOctetsAdded;
	appendIdentifierOctet(TAG_SET, CONSTRUCTED, UNIVERSAL, certificateBuffer, certificate_ptr);
	*len3= *len3 +1;
	* totalLength = *totalLength + 1;
	//Added CN
	
	
	
	
	
	addHashToBuffer(certificateBuffer, organizationalUnitName, certificate_ptr, strlen(organizationalUnitName));
	
	*len5 = strlen(organizationalUnitName);
	*totalLength= *totalLength + strlen(organizationalUnitName);
	
	numOctetsAdded = appendLengthToBuffer( strlen(organizationalUnitName), certificateBuffer, certificate_ptr);
	*len5= *len5 + numOctetsAdded;
	*totalLength= *totalLength + numOctetsAdded;
	
	appendIdentifierOctet(TAG_UTF8_STRING, PRIMITIVE, UNIVERSAL, certificateBuffer, certificate_ptr);
	*len5= *len5 + 1;
	* totalLength = *totalLength + 1;
	
	addOID(certificateBuffer, certificate_ptr, OUN_OID);
	*len5= *len5 + strlen(OUN_OID)/2;
	*totalLength= *totalLength + strlen(OUN_OID)/2;
	
	numOctetsAdded = appendLengthToBuffer( strlen(OUN_OID)/2 , certificateBuffer, certificate_ptr);
	*len5= *len5 + numOctetsAdded;
	*totalLength= *totalLength + numOctetsAdded;
	
	appendIdentifierOctet(TAG_OID, PRIMITIVE, UNIVERSAL, certificateBuffer, certificate_ptr);
	*len5= *len5 + 1;
	* totalLength = *totalLength + 1;
	
	*len4 = *len5;
	numOctetsAdded = appendLengthToBuffer( *len5, certificateBuffer, certificate_ptr);
	*len4 = *len4 + numOctetsAdded;;
	*totalLength= *totalLength + numOctetsAdded;
	appendIdentifierOctet(TAG_SEQUENCE, CONSTRUCTED, UNIVERSAL, certificateBuffer, certificate_ptr);
	*len4 = *len4 + 1;;
	* totalLength = *totalLength + 1;
	
	*len3 = *len3 + *len4;
	numOctetsAdded = appendLengthToBuffer( *len4, certificateBuffer, certificate_ptr);
	*len3= *len3 +numOctetsAdded;
	*totalLength= *totalLength + numOctetsAdded;
	appendIdentifierOctet(TAG_SET, CONSTRUCTED, UNIVERSAL, certificateBuffer, certificate_ptr);
	*len3= *len3 +1;
	* totalLength = *totalLength + 1;
	// Added organizationUnitName
	
	
	addHashToBuffer(certificateBuffer, localityName, certificate_ptr, strlen(orgName));
	
	*len5 = strlen(orgName);
	*totalLength= *totalLength + strlen(orgName);
	
	numOctetsAdded = appendLengthToBuffer( strlen(orgName), certificateBuffer, certificate_ptr);
	*len5= *len5 + numOctetsAdded;
	*totalLength= *totalLength + numOctetsAdded;
	
	appendIdentifierOctet(TAG_UTF8_STRING, PRIMITIVE, UNIVERSAL, certificateBuffer, certificate_ptr);
	*len5= *len5 + 1;
	* totalLength = *totalLength + 1;
	
	addOID(certificateBuffer, certificate_ptr, ORG_OID);
	*len5= *len5 + strlen(ORG_OID)/2;
	*totalLength= *totalLength + strlen(ORG_OID)/2;
	
	numOctetsAdded = appendLengthToBuffer( strlen(ORG_OID)/2 , certificateBuffer, certificate_ptr);
	*len5= *len5 + numOctetsAdded;
	*totalLength= *totalLength + numOctetsAdded;
	
	appendIdentifierOctet(TAG_OID, PRIMITIVE, UNIVERSAL, certificateBuffer, certificate_ptr);
	*len5= *len5 + 1;
	* totalLength = *totalLength + 1;
	
	*len4 = *len5;
	numOctetsAdded = appendLengthToBuffer( *len5, certificateBuffer, certificate_ptr);
	*len4 = *len4 + numOctetsAdded;;
	*totalLength= *totalLength + numOctetsAdded;
	appendIdentifierOctet(TAG_SEQUENCE, CONSTRUCTED, UNIVERSAL, certificateBuffer, certificate_ptr);
	*len4 = *len4 + 1;;
	* totalLength = *totalLength + 1;
	
	*len3 = *len3 + *len4;
	numOctetsAdded = appendLengthToBuffer( *len4, certificateBuffer, certificate_ptr);
	*len3= *len3 +numOctetsAdded;
	*totalLength= *totalLength + numOctetsAdded;
	appendIdentifierOctet(TAG_SET, CONSTRUCTED, UNIVERSAL, certificateBuffer, certificate_ptr);
	*len3= *len3 +1;
	* totalLength = *totalLength + 1;
	
	// ADDED ORGANIZTION NAME
	
	addHashToBuffer(certificateBuffer, localityName, certificate_ptr, strlen(localityName));
	
	*len5 = strlen(localityName);
	*totalLength= *totalLength + strlen(localityName);
	
	numOctetsAdded = appendLengthToBuffer( strlen(localityName), certificateBuffer, certificate_ptr);
	*len5= *len5 + numOctetsAdded;
	*totalLength= *totalLength + numOctetsAdded;
	
	appendIdentifierOctet(TAG_UTF8_STRING, PRIMITIVE, UNIVERSAL, certificateBuffer, certificate_ptr);
	*len5= *len5 + 1;
	* totalLength = *totalLength + 1;
	
	addOID(certificateBuffer, certificate_ptr, LOC_OID);
	*len5= *len5 + strlen(LOC_OID)/2;
	*totalLength= *totalLength + strlen(LOC_OID)/2;
	
	numOctetsAdded = appendLengthToBuffer( strlen(LOC_OID)/2 , certificateBuffer, certificate_ptr);
	*len5= *len5 + numOctetsAdded;
	*totalLength= *totalLength + numOctetsAdded;
	
	appendIdentifierOctet(TAG_OID, PRIMITIVE, UNIVERSAL, certificateBuffer, certificate_ptr);
	*len5= *len5 + 1;
	* totalLength = *totalLength + 1;
	
	*len4 = *len5;
	numOctetsAdded = appendLengthToBuffer( *len5, certificateBuffer, certificate_ptr);
	*len4 = *len4 + numOctetsAdded;;
	*totalLength= *totalLength + numOctetsAdded;
	appendIdentifierOctet(TAG_SEQUENCE, CONSTRUCTED, UNIVERSAL, certificateBuffer, certificate_ptr);
	*len4 = *len4 + 1;;
	* totalLength = *totalLength + 1;
	
	*len3 = *len3 + *len4;
	numOctetsAdded = appendLengthToBuffer( *len4, certificateBuffer, certificate_ptr);
	*len3= *len3 +numOctetsAdded;
	*totalLength= *totalLength + numOctetsAdded;
	appendIdentifierOctet(TAG_SET, CONSTRUCTED, UNIVERSAL, certificateBuffer, certificate_ptr);
	*len3= *len3 +1;
	* totalLength = *totalLength + 1;
	
	//Added Locality

	addHashToBuffer(certificateBuffer, state, certificate_ptr, strlen(state));
	
	*len5 = strlen(state);
	*totalLength= *totalLength + strlen(state);
	
	numOctetsAdded = appendLengthToBuffer( strlen(state), certificateBuffer, certificate_ptr);
	*len5= *len5 + numOctetsAdded;
	*totalLength= *totalLength + numOctetsAdded;
	
	appendIdentifierOctet(TAG_UTF8_STRING, PRIMITIVE, UNIVERSAL, certificateBuffer, certificate_ptr);
	*len5= *len5 + 1;
	* totalLength = *totalLength + 1;
	
	addOID(certificateBuffer, certificate_ptr, STATE_OID);
	*len5= *len5 + strlen(STATE_OID)/2;
	*totalLength= *totalLength + strlen(STATE_OID)/2;
	
	numOctetsAdded = appendLengthToBuffer( strlen(STATE_OID)/2 , certificateBuffer, certificate_ptr);
	*len5= *len5 + numOctetsAdded;
	*totalLength= *totalLength + numOctetsAdded;
	
	appendIdentifierOctet(TAG_OID, PRIMITIVE, UNIVERSAL, certificateBuffer, certificate_ptr);
	*len5= *len5 + 1;
	* totalLength = *totalLength + 1;
	
	*len4 = *len5;
	numOctetsAdded = appendLengthToBuffer( *len5, certificateBuffer, certificate_ptr);
	*len4 = *len4 + numOctetsAdded;;
	*totalLength= *totalLength + numOctetsAdded;
	appendIdentifierOctet(TAG_SEQUENCE, CONSTRUCTED, UNIVERSAL, certificateBuffer, certificate_ptr);
	*len4 = *len4 + 1;;
	* totalLength = *totalLength + 1;
	
	*len3 = *len3 + *len4;
	numOctetsAdded = appendLengthToBuffer( *len4, certificateBuffer, certificate_ptr);
	*len3= *len3 +numOctetsAdded;
	*totalLength= *totalLength + numOctetsAdded;
	appendIdentifierOctet(TAG_SET, CONSTRUCTED, UNIVERSAL, certificateBuffer, certificate_ptr);
	*len3= *len3 +1;
	* totalLength = *totalLength + 1;
	// state
	
	addHashToBuffer(certificateBuffer, country, certificate_ptr, strlen(country));
	
	*len5 = strlen(country);
	*totalLength= *totalLength + strlen(country);
	
	numOctetsAdded = appendLengthToBuffer( strlen(country), certificateBuffer, certificate_ptr);
	*len5= *len5 + numOctetsAdded;
	*totalLength= *totalLength + numOctetsAdded;
	
	appendIdentifierOctet(TAG_UTF8_STRING, PRIMITIVE, UNIVERSAL, certificateBuffer, certificate_ptr);
	*len5= *len5 + 1;
	* totalLength = *totalLength + 1;
	
	addOID(certificateBuffer, certificate_ptr, Country_OID);
	*len5= *len5 + strlen(Country_OID)/2;
	*totalLength= *totalLength + strlen(Country_OID)/2;
	
	numOctetsAdded = appendLengthToBuffer( strlen(Country_OID)/2 , certificateBuffer, certificate_ptr);
	*len5= *len5 + numOctetsAdded;
	*totalLength= *totalLength + numOctetsAdded;
	
	appendIdentifierOctet(TAG_OID, PRIMITIVE, UNIVERSAL, certificateBuffer, certificate_ptr);
	*len5= *len5 + 1;
	* totalLength = *totalLength + 1;
	
	*len4 = *len5;
	numOctetsAdded = appendLengthToBuffer( *len5, certificateBuffer, certificate_ptr);
	*len4 = *len4 + numOctetsAdded;;
	*totalLength= *totalLength + numOctetsAdded;
	appendIdentifierOctet(TAG_SEQUENCE, CONSTRUCTED, UNIVERSAL, certificateBuffer, certificate_ptr);
	*len4 = *len4 + 1;;
	* totalLength = *totalLength + 1;
	
	*len3 = *len3 + *len4;
	numOctetsAdded = appendLengthToBuffer( *len4, certificateBuffer, certificate_ptr);
	*len3= *len3 +numOctetsAdded;
	*totalLength= *totalLength + numOctetsAdded;
	appendIdentifierOctet(TAG_SET, CONSTRUCTED, UNIVERSAL, certificateBuffer, certificate_ptr);
	*len3= *len3 +1;
	* totalLength = *totalLength + 1;
		
	// country
	
}



void addSignAlgorithmHeader(int *certificateBuffer, int* index, int* totalLength)
{
	int lengthUsualHeader = 0, numOctetsAdded = 0;
	int protoLen = strlen(md5WithRSAEnc)/2;
	//adds 00 length of NULL
	addNullOctet(certificateBuffer, index);
	*totalLength = *totalLength + 1;
	lengthUsualHeader++;
	
	//printf("Total octets 2 %d", *totalLength);
	//Adding identifier octet for NULL -- 05
	appendIdentifierOctet(TAG_NULL, PRIMITIVE, UNIVERSAL, certificateBuffer, index);
	*totalLength = *totalLength + 1;
	lengthUsualHeader++;
	
	//printf("Total octets 3 %d", *totalLength);
	//This adds 9 octets
	addOID(certificateBuffer, index, md5WithRSAEnc);
	//One octet for 2 hex characters
	*totalLength = *(totalLength) + protoLen;
	lengthUsualHeader = lengthUsualHeader + protoLen;
	
	
	//This ideally adds 1 octet - more if length is high
	numOctetsAdded = appendLengthToBuffer( protoLen , certificateBuffer, index);
	*totalLength= *(totalLength) + numOctetsAdded;
	lengthUsualHeader+= numOctetsAdded;
	
	//The indentifier octet
	appendIdentifierOctet(TAG_OID, PRIMITIVE, UNIVERSAL, certificateBuffer, index);
	*totalLength = *totalLength + 1;
	lengthUsualHeader++;
	
	numOctetsAdded = appendLengthToBuffer( lengthUsualHeader , certificateBuffer, index);
	*totalLength= *totalLength + numOctetsAdded;
			
	appendIdentifierOctet(TAG_SEQUENCE, CONSTRUCTED, UNIVERSAL, certificateBuffer, index);
	*totalLength = *totalLength + 1;
	
}
