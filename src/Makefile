CC     = gcc
CFLAGS = -fstrict-aliasing -Wall
IFLAGS = -g root -o root

OUT       = dump_sap dump_udp relay tvbr tvbr-unicast-client tvbr-unicast-server
COMMON    = udpsocket.o
SRC_FILES = $(wildcard *.c)

BINDIR = ../bin

ifdef DEBUG
  CFLAGS += -g
else
  CFLAGS += -O2
endif

.PHONY: all clean clean_objs install uninstall

all: $(COMMON) $(OUT)

dump_sap: dump_sap.c $(COMMON)
	$(CC) $(CFLAGS) -o $@ -lz $< $(COMMON)

tvbr: tvbr.c tvbr-stream.o tvbr-dvb.o tvbr-sap.o tvbr-config.o $(COMMON)
	$(CC) $(CFLAGS) -o $@ -lpthread $< $(COMMON) tvbr-stream.o tvbr-dvb.o tvbr-sap.o tvbr-config.o

tvbr-unicast-client: tvbr-unicast-client.c tvbr-unicast-ipc.o $(COMMON)
	$(CC) $(CFLAGS) -o $@ $< $(COMMON) tvbr-unicast-ipc.o

tvbr-unicast-server: tvbr-unicast-server.c tvbr-unicast-ipc.o $(COMMON)
	$(CC) $(CFLAGS) -o $@ $< $(COMMON) tvbr-unicast-ipc.o

%: %.c $(COMMON)
	$(CC) $(CFLAGS) -o $@ $< $(COMMON)

clean: clean_objs
	-rm -f $(OUT)

clean_objs:
	-rm -f *.o *~ .depend

install: $(OUT)
	install $(IFLAGS) -d $(BINDIR)
	install $(IFLAGS) -m 755 $(OUT) $(BINDIR)

uninstall:
	-rm $(foreach file,$(OUT),$(BINDIR)/$(file))

.c.o:
	$(CC) $(CFLAGS) -c $<

.depend: $(SRC_FILES)
	$(CC) -MM $^ > $@

include .depend
