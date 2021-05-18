PKGCONF = pkg-config

APP = dpdk-qdispatcher
SRCS-y = qdispatcher.c 

CFLAGS += -I./ -Wall -g -O3 $(shell $(PKGCONF) --cflags libdpdk)
LDFLAGS += $(shell $(PKGCONF) --libs libdpdk)

$(APP): $(SRCS-y) qdispatcher.h Makefile
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS)

clean:
	rm -rf $(APP)
