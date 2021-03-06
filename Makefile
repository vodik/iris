CFLAGS := -std=c11 -g \
	-Wall -Wextra -pedantic \
	-Wshadow -Wpointer-arith -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes \
	-Wno-missing-field-initializers \
	-D_GNU_SOURCE \
	$(CFLAGS)

LDLIBS = -lssl -lcrypto

all: iris
debug: CFLAGS += -fsanitize=address -fsanitize=undefined -fsanitize=integer
debug: LDFLAGS += -fsanitize=address -fsanitize=undefined -fsanitize=integer
debug: iris

iris: iris.o imap.o smtp.o socket.o base64.o

clean:
	$(RM) *.o iris

.PHONY: all clean
