all: sendarp
	
sendarp: sendarp.c
	gcc -o sendarp sendarp.c
clean: 
	rm sendarp
