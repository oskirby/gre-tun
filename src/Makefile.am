bin_PROGRAMS = gre-tunneld

# GRE Tunnel Daemon
gre_tunneld_CFLAGS = ${GNUTLS_CFLAGS}
gre_tunneld_LDADD = ${GNUTLS_LIBS}
gre_tunneld_SOURCES = main.c
gre_tunneld_SOURCES += gre-common.c
gre_tunneld_SOURCES += gre-client.c
gre_tunneld_SOURCES += gre-server.c
gre_tunneld_SOURCES += gre.h
