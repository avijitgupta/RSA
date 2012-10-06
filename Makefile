all: rsaengine

rsaengine: main.o encrypt.o sign.o keyParser.o generate.o decrypt.o
	   gcc main.o encrypt.o sign.o keyParser.o generate.o decrypt.o -o rsaengine -lgmp -lssl -lcrypto

generate.o: generate.c
	    gcc -c generate.c -lgmp

keyparser.o: keyParser.c
	     gcc -c keyParser.c -lgmp

encrypt.o:   encrypt.c
	     gcc -c encrypt.c -lgmp

main.o:	     main.c
	     gcc -c main.c -lgmp

decrypt.o:   decrypt.c
	     gcc -c decrypt.c -lgmp

sign.o:	     sign.c
	     gcc -c sign.c -lgmp -lssl -lcrypto

clean:	     
	rm -f *.o
	rm -f rsaengine
