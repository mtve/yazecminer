PROG	= jazecminer.js
MAIN	= main.bc
OBJ	= blake2b.bc equihash.bc sha256.bc $(MAIN)
HDR	= blake2b.h sha256.h equihash.h util.h

EMCC	= emcc
EMCC	+= -g -W -Wall -O3
EMCC	+= -s WASM=1
EMCC	+= -s TOTAL_MEMORY=256MB
EMCC	+= -s EXPORTED_FUNCTIONS='["_mine"]'

$(PROG): $(OBJ)
	$(EMCC) -o $(PROG) $(OBJ)

%.bc: %.c $(HDR)
	$(EMCC) -o $@ $<

clean:
	rm -f $(PROG) $(OBJ)
