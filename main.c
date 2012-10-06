#include "rsahelper.h"

void displayOptions()
{
	
}

int main (int argc, char **argv)
{
		int c;
		int generate = 0, encr = 0 , decr = 0, pubin = 0, privin = 0, parse =0, sign = 0, verifyData = 0;
		char file1[LEN_FILE_NAME];
		memset(file1, 0, LEN_FILE_NAME);
		char file2[LEN_FILE_NAME];
		memset(file2, 0, LEN_FILE_NAME);
		char file3[LEN_FILE_NAME];
		memset(file3, 0, LEN_FILE_NAME);
		char file4[LEN_FILE_NAME];
		memset(file4, 0, LEN_FILE_NAME);
		
		while(1)
		{
			int option_index = 0;
			static struct option long_options[] = {
				{"genrsa", no_argument, 			0,  'g' },
				{"privout",  required_argument, 	0,  'r' },
				{"pubout",  required_argument, 		0,  'u' },
				{"help",  required_argument, 		0,  'h' },
				{"encrypt", no_argument,       		0,  'e' },
				{"privin",    required_argument, 	0,  'i' },
				{"out",  required_argument, 		0, 	'o'	},
				{"decrypt", no_argument,       		0,  'd' },
				{"pubin",    required_argument, 	0,  'b' },
				{"in",    required_argument,		0,  'I' },
				{"asn1parse", required_argument, 	0, 	'a'	},
				{"sign", no_argument,				0,	's'	},
				{"verify", no_argument,				0,	'v'	},
				{"message", required_argument, 		0, 	'm'}			 
			};
		
			c = getopt_long_only(argc, argv, "", long_options, &option_index);
			
			if(c == -1)break;
			
			switch(c)
			{
					case 'g':	generate = 1;
								break;
					case 'r':	if(optarg)
									strcpy(file1, optarg);
								else
									displayOptions();
								break;
					case 'u':	if(optarg)
									strcpy(file2, optarg);
								else
									displayOptions();
								break;
					//Encryption / dec options
					case 'e':	encr = 1;
								break;
					case 'd':	decr = 1;
								break;
								//out file
					case 'o':	if(optarg)
									strcpy(file3, optarg);
								else
									displayOptions();
								break;
								//private in
					case 'i':	if(optarg)
								{
									strcpy(file1, optarg);
									privin = 1;
								}
								else
									displayOptions();
								break;
								//public in
					case 'b':	if(optarg)
								{
									pubin = 1;
									strcpy(file2, optarg);
								}
								else
									displayOptions();
								break;
					case 'I': 	if(optarg)
									strcpy(file4, optarg);
								else
									displayOptions();
								break;
					case 'a':	if(optarg)
								{
									strcpy(file4, optarg);
									parse = 1;
								}
								else
									displayOptions();
								break;	
					case 's':	sign = 1;
								break;
					case 'v':	verifyData = 1;
								break;
					case 'm':	if(optarg)
									strcpy(file1, optarg);
								else
									displayOptions();
			}
			
			
		}
		
		
		if(parse == 1)
		{
			parse_display(file4);
			return 0;
		}
		
		else if(generate == 1)
		{
				if(strcmp(file1, file2)!=0)
				{
					if(strlen(file1) == 0 || strlen(file2) == 0)
					{
							printf("Specify public/private key Filename\n");
							return 1;
					}
					else
					{
						genrsa(file1, file2);
					}
				}
				else
				{
						printf("Specify different names for private and public keys \n");
				}
		}
		
		//Encrytion supported with either private/public key
		else if(encr == 1)
		{
			if( !(pubin ^ privin))
			{
				printf("Cannot specify more than one key, or no key files\n");
				return 1;
			}
			int ret = 0;
			if(pubin)
			{
				ret = encrypt(file4, file3, file2, PUBLIC_KEY);
			}
			else if(privin)
			{
				ret = encrypt(file4, file3, file1, PRIVATE_KEY);	
			}
			return ret;
		}
		else if(decr == 1)
		{
			if( !(pubin ^ privin))
			{
				printf("Cannot specify more than one key, or no key files\n");
				return 1;
			}
			int ret = 0;
			if(pubin)
			{
				ret = decrypt(file4, file3, file2, PUBLIC_KEY, NULL, NULL);
			}
			else if(privin)
			{
				ret = decrypt(file4, file3, file1, PRIVATE_KEY, NULL, NULL);	
			}
			return ret;
		}
		else if (sign ==1)
		{
				generateSign(file4, file1, file3); 
		}
		else if(verifyData == 1)
		{
				verify(file4, file1, file2);
		}
}
