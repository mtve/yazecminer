PROG	= yazecminer
OBJ	= jsmn/jsmn.o sha256/sha256.o equihash.o mainer.o
HDR	= blake2b.h sha256/sha256.h equihash.h

#BLAKE	= ref
BLAKE	= sse
OBJ	+= blake2b-$(BLAKE)/blake2b.o 

CC	= gcc
CFLAGS	= -march=native -W -Wall -O3 -g -I.
#LDFLAGS = -static
#LDFLAGS += -lsocket -lnsl

$(PROG): $(OBJ)
	$(CC) $(LDFLAGS) -o $(PROG) $(OBJ)

$(OBJ): $(HDR)

clean:
	rm -f $(PROG) $(OBJ)
