CC = gcc
LD = $(CC)
RM = rm -f
CFLAGS = -Wall -W -O2 -fomit-frame-pointer
LDFLAGS = -s

PROJ = lkrg-logger lkrg-logctl lkrg-keygen
LOGGER_OBJS = logger.o misc.o session.o
LOGCTL_OBJS = logctl.o
KEYGEN_OBJS = keygen.o
OBJS = $(LOGGER_OBJS) $(LOGCTL_OBJS) $(KEYGEN_OBJS)

all: $(PROJ)

lkrg-logger: $(LOGGER_OBJS)
	$(LD) $(LDFLAGS) $(LOGGER_OBJS) -o $@

lkrg-logctl: $(LOGCTL_OBJS)
	$(LD) $(LDFLAGS) $(LOGCTL_OBJS) -o $@

lkrg-keygen: $(KEYGEN_OBJS)
	$(LD) $(LDFLAGS) $(KEYGEN_OBJS) -o $@

.c.o:
	$(CC) $(CFLAGS) -c $*.c

clean:
	$(RM) $(PROJ) $(OBJS)
