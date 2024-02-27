CC = gcc
LD = $(CC)
RM = rm -f
MKDIR = mkdir -p
INSTALL = install -c
CFLAGS = -Wall -W -O2 -fomit-frame-pointer
LDFLAGS = -s

DESTDIR =
PREFIX = /usr/local
SBINDIR = $(PREFIX)/sbin
UNITDIR = /etc/systemd/system

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

install: $(PROJ)
	$(MKDIR) -m 755 $(DESTDIR)$(SBINDIR)
	$(INSTALL) -m 700 lkrg-logger $(DESTDIR)$(SBINDIR)/
	$(INSTALL) -m 700 lkrg-logctl $(DESTDIR)$(SBINDIR)/
	$(INSTALL) -m 755 lkrg-keygen $(DESTDIR)$(SBINDIR)/
	if [ -d $(DESTDIR)$(UNITDIR) ]; then \
		umask 022; \
		sed "s,/usr,$(PREFIX)," lkrg-logger.service > $(DESTDIR)$(UNITDIR)/lkrg-logger.service; \
	fi

uninstall:
	$(RM) $(DESTDIR)$(SBINDIR)/lkrg-{logger,logctl,keygen} $(DESTDIR)$(UNITDIR)/lkrg-logger.service

clean:
	$(RM) $(PROJ) $(OBJS)
