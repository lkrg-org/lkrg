CC = gcc
LD = $(CC)
RM = rm -f
MKDIR = mkdir -p
INSTALL = install -c
# -pie is a linker option. but let's have it in CFLAGS to ensure -fPIE and -pie
# are ever overridden or not together
CFLAGS = -Wall -W -O2 -fomit-frame-pointer -fPIE -pie -fstack-protector-strong -D_FORTIFY_SOURCE=2
# Include CFLAGS into LDFLAGS for two reasons:
# 1. "For predictable results, you must also specify the same set of options
#    used for compilation (-fpie, -fPIE, or model suboptions) when you specify
#    this linker option." (as gcc man page says about "-pie")
# 2. In case the package only overrides CFLAGS, we want the distro's hardening
#    or other flags to also propagate to the linker.
LDFLAGS = -s -Wl,-z,defs -Wl,-z,relro -Wl,-z,now $(CFLAGS)

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
	$(INSTALL) -m 755 lkrg-logctl $(DESTDIR)$(SBINDIR)/
	$(INSTALL) -m 755 lkrg-keygen $(DESTDIR)$(SBINDIR)/
	if [ -d $(DESTDIR)$(UNITDIR) ]; then \
		umask 022; \
		sed "s,/usr,$(PREFIX)," lkrg-logger.service > $(DESTDIR)$(UNITDIR)/lkrg-logger.service; \
	fi

uninstall:
	$(RM) $(DESTDIR)$(SBINDIR)/lkrg-{logger,logctl,keygen} $(DESTDIR)$(UNITDIR)/lkrg-logger.service

clean:
	$(RM) $(PROJ) $(OBJS)
