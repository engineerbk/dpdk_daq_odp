AUTOMAKE_OPTIONS = foreign

ACLOCAL_AMFLAGS = -I m4

pkglib_LTLIBRARIES = daq_odp.la
daq_odp_la_SOURCES = daq_odp.c
daq_odp_la_CFLAGS = -DBUILDING_SO -m64 -march=corei7 -I../../x86_64-native-linuxapp-gcc/include -Wl,--no-as-needed
daq_odp_la_LDFLAGS = -module -export-dynamic -avoid-version -shared -lodp  -m64 -march=corei7 -I../../x86_64-native-linuxapp-gcc/lib -Wl,--no-as-needed

