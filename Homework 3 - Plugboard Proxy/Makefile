CC = gcc

LIBS = -lpthread -lcrypto

FLAGS = -g -Wno-unused-result -Werror=unused-variable

all: pbproxy 

pbproxy:
	${CC} ${FLAGS} pbproxy.c pbserver.c pbclient.c crypto.c -o pbproxy ${LIBS}

clean:
	rm pbproxy