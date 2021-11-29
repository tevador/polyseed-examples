cpptest: pbkdf2.o polyseed.o main2.o
	g++ -g $^ -lpolyseed -lboost_locale -lsodium -o $@

pbkdf2.o: pbkdf2.c pbkdf2.h
	gcc -g -c pbkdf2.c -Wall

polyseed.o: polyseed.cpp polyseed.hpp
	g++ -g -c polyseed.cpp -Wall

main2.o: main2.cpp
	g++ -g -c main2.cpp -Wall
