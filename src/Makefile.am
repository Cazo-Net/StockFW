gladedir = $(datadir)/stockfw/glade/
SUBDIRS = xpm

INCLUDES = \
	$(WARN_CFLAGS) \
	@STOCKFW_CFLAGS@ \
	-DG_LOG_DOMAIN=\"StockFW\" \
	-DSTOCKFW_RULES_DIR=\"@sysconfdir@\" \
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\" \
	-DGLADEDIR=\""$(datadir)/stockfw/glade"\"

bin_PROGRAMS = stockfw

stockfw_SOURCES = \
	stockfw.c	\
	gui.c		\
	util.c		\
	logread.c	\
	menus.c  	\
	wizard.c 	\
	wizard-choices.c \
	service.c	\
	preferences.c	\
	scriptwriter.c	\
	savelog.c	\
	netfilter-script.c \
	hitview.c	\
	eggtrayicon.c	\
	tray.c		\
	dhcp-server.c	\
	statusview.c	\
	policyview.c	\
	globals.h	\
	stockfw.h	\
	gui.h		\
	util.h		\
	logread.h	\
	menus.h  	\
	wizard.h 	\
	wizard-choices.h \
	service.h	\
	preferences.h	\
	scriptwriter.h	\
	savelog.h	\
	netfilter-script.h \
	hitview.h	\
	eggtrayicon.h	\
	tray.h		\
	dhcp-server.h	\
	statusview.h	\
	policyview.h

glade_DATA = \
	preferences.glade

stockfw_LDADD = @STOCKFW_LIBS@

EXTRA_DIST = $(glade_DATA)
