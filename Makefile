all: rsaengine

rsaengine: main.o encrypt.o keyParser.o generate.o 
	   gcc main.o encrypt.o keyParser.o generate.o -o rsaengine -lgmp

generate.o: generate.c
	    gcc -c generate.c -lgmp

keyparser.o: keyParser.c
	     gcc -c keyParser.c -lgmp

encrypt.o:   encrypt.c
	     gcc -c encrypt.c -lgmp

main.o:	     main.c
	     gcc -c main.c -lgmp
