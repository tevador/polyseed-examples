ctest: pbkdf2.o main1.o
	gcc -g $^ -lpolyseed -lutf8proc -lsodium -o $@

pbkdf2.o: pbkdf2.c pbkdf2.h
	gcc -g -c pbkdf2.c -Wall

main1.o: main1.c
	gcc -g -c main1.c -Wall
