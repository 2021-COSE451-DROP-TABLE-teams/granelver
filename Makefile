ifndef CROSS_CC_PREFIX
	CROSS_CC_PREFIX=$(CROSS_COMPILE)
endif

CC=$(CROSS_CC_PREFIX)gcc
LD=$(CROSS_CC_PREFIX)ld
STRIP=$(CROSS_CC_PREFIX)strip

CFLAGS = -Wall -Os -fdata-sections -ffunction-sections

SRC = granelver.c pwned.html
OBJ = granelver.o pwned.o

%.gz: %.html
	gzip -c $< > $@

%.o: %.gz
	$(LD) -r -b binary -o $@ $<

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

granelver: $(OBJ)
	$(CC) -static -Wl,--gc-sections -o $@ $^ $(CFLAGS)
	$(STRIP) $@

all: granelver

clean:
	rm -f *.o *.gz granelver
