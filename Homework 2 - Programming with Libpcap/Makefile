CC = gcc

LIBS = -lpcap
	
FLAGS = -g -O2

all: mydump 

mydump: mydump.o 
	${CC} ${FLAGS} -o mydump mydump.o ${LIBS}
mydump.o: mydump.c
	${CC} ${FLAGS} -c mydump.c

clean:
	rm mydump.o mydump

