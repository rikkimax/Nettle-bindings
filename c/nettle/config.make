# Makefile settings shared between Makefiles.

CC = gcc
CXX = g++
CFLAGS = -g -O2 -ggdb3 -Wno-pointer-sign -Wall -W   -Wmissing-prototypes -Wmissing-declarations -Wstrict-prototypes   -Wpointer-arith -Wbad-function-cast -Wnested-externs
CXXFLAGS = -g -O2
CCPIC = 
CCPIC_MAYBE = 
CPPFLAGS = 
DEFS = -DHAVE_CONFIG_H
LDFLAGS = 
LIBS = 
LIBOBJS =  ${LIBOBJDIR}memxor$U.o
EMULATOR = 
NM = nm

OBJEXT = o
EXEEXT = .exe

CC_FOR_BUILD = gcc
EXEEXT_FOR_BUILD = .exe

DEP_FLAGS = -MT $@ -MD -MP -MF $@.d
DEP_PROCESS = true

PACKAGE_BUGREPORT = nettle-bugs@lists.lysator.liu.se
PACKAGE_NAME = nettle
PACKAGE_STRING = nettle 2.7.1
PACKAGE_TARNAME = nettle
PACKAGE_VERSION = 2.7.1

SHLIBCFLAGS = 

LIBNETTLE_MAJOR = 4
LIBNETTLE_MINOR = 7
LIBNETTLE_SONAME = 
LIBNETTLE_FILE = libnettle.dll.a
LIBNETTLE_FILE_SRC = $(LIBNETTLE_FILE)
LIBNETTLE_FORLINK = cygnettle-$(LIBNETTLE_MAJOR)-$(LIBNETTLE_MINOR).dll
LIBNETTLE_LIBS = -Wl,--no-whole-archive $(LIBS)
LIBNETTLE_LINK = $(CC) $(CFLAGS) $(LDFLAGS) -shared -Wl,--out-implib=$(LIBNETTLE_FILE) -Wl,--export-all-symbols -Wl,--enable-auto-import -Wl,--whole-archive

LIBHOGWEED_MAJOR = 2
LIBHOGWEED_MINOR = 5
LIBHOGWEED_SONAME = 
LIBHOGWEED_FILE = libhogweed.dll.a
LIBHOGWEED_FILE_SRC = $(LIBHOGWEED_FILE)
LIBHOGWEED_FORLINK = cyghogweed-$(LIBHOGWEED_MAJOR)-$(LIBHOGWEED_MINOR).dll
LIBHOGWEED_LIBS = -Wl,--no-whole-archive $(LIBS) libnettle.dll.a
LIBHOGWEED_LINK = $(CC) $(CFLAGS) $(LDFLAGS) -shared -Wl,--out-implib=$(LIBHOGWEED_FILE) -Wl,--export-all-symbols -Wl,--enable-auto-import -Wl,--whole-archive

GMP_NUMB_BITS = 0

AR = ar
ARFLAGS = cru
AUTOCONF = autoconf
AUTOHEADER = autoheader
M4 = m4
MAKEINFO = makeinfo
RANLIB = ranlib
LN_S = ln -s

prefix	=	/usr/local
exec_prefix =	${prefix}
datarootdir =	${prefix}/share
bindir =	${exec_prefix}/bin
libdir =	${exec_prefix}/lib
includedir =	${prefix}/include
infodir =	${datarootdir}/info

# PRE_CPPFLAGS and PRE_LDFLAGS lets each Makefile.in prepend its own
# flags before CPPFLAGS and LDFLAGS.

COMPILE = $(CC) $(PRE_CPPFLAGS) $(CPPFLAGS) $(DEFS) $(CFLAGS) $(CCPIC) $(DEP_FLAGS)
COMPILE_CXX = $(CXX) $(PRE_CPPFLAGS) $(CPPFLAGS) $(DEFS) $(CXXFLAGS) $(CCPIC) $(DEP_FLAGS)
LINK = $(CC) $(CFLAGS) $(PRE_LDFLAGS) $(LDFLAGS)
LINK_CXX = $(CXX) $(CXXFLAGS) $(PRE_LDFLAGS) $(LDFLAGS)

# Default rule. Must be here, since config.make is included before the
# usual targets.
default: all

# For some reason the suffixes list must be set before the rules.
# Otherwise BSD make won't build binaries e.g. aesdata. On the other
# hand, AIX make has the opposite idiosyncrasies to BSD, and the AIX
# compile was broken when .SUFFIXES was moved here from Makefile.in.

.SUFFIXES:
.SUFFIXES: .asm .s .c .$(OBJEXT) .p$(OBJEXT) .html .dvi .info .exe .pdf .ps .texinfo

# Disable builtin rule
%$(EXEEXT) : %.c
.c:

# Keep object files
.PRECIOUS: %.o

.PHONY: all check install uninstall clean distclean mostlyclean maintainer-clean distdir \
	all-here check-here install-here clean-here distclean-here mostlyclean-here \
	maintainer-clean-here distdir-here \
	install-shared install-info install-headers \
	uninstall-shared uninstall-info uninstall-headers \
	dist distcleancheck
