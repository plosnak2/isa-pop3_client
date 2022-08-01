CC=g++
CFLAGS=-std=c++17
LDLIBS = -lssl -lcrypto


all: 
	$(CC) $(CFLAGS) popcl.cpp -o popcl $(LDLIBS)
