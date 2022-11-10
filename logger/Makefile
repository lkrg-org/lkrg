CC = gcc
LD = $(CC)
RM = rm -f
CFLAGS = -Wall -W -O2 -fomit-frame-pointer
LDFLAGS = -s

PROJ = lkrg-logger lkrg-keygen
LOGGER_OBJS = logger.o misc.o session.o
KEYGEN_OBJS = keygen.o
OBJS = $(LOGGER_OBJS) $(KEYGEN_OBJS)

all: $(PROJ)

lkrg-logger: $(LOGGER_OBJS)
	$(LD) $(LDFLAGS) $(LOGGER_OBJS) -o $@

lkrg-keygen: $(KEYGEN_OBJS)
	$(LD) $(LDFLAGS) $(KEYGEN_OBJS) -o $@

.c.o:
	$(CC) $(CFLAGS) -c $*.c

clean:
	$(RM) $(PROJ) $(OBJS)
