OpenDataPlane DPDK DAQ Module
========================

The OpenDataPlane project is an open-source, cross-platform set of application programming interfaces (APIs) for the networking data plane.  This module uses OpenDataPlane to receive and send packet data in a manner that conforms to the DAQ Module API.

This module was designed and tested with OpenDataPlane v1.6.0.0 and DPDK v2.2.0.  Their project is still under heavy development and the APIs are very much in flux, meaning that this module will likely not build cleanly against newer versions.

As there are no released source tarballs yet, you must clone the OpenDataPlane GIT repository and build from that.  To checkout, build, and install OpenDataPlane:

    install DPDK ver 2.2.0 from dpdk.org site.
    git clone https://git.linaro.org/lng/odp.git -b v1.6.0.0 odp-v1.6.0.0
    cd odp-v1.6.0.0
    ./bootstrap
    ./configure
    make
    make install

If you installed OpenDataPlane into a non-standard location, you will need to use the --with-odp-includes and --with-odp-libraries switches for the DAQ module's configure script.

To specify multiple interfaces, simply provide a string of comma-separated interface names.  If the DAQ module is configured for inline operation, every two interfaces specified is considered a pair and an error will be thrown if there are an uneven number of interfaces.

Supported DAQ variables:

    debug - Enable some additional debugging output printed to stdout.

Example:

    ./snort -Q --daq-dir /usr/local/lib/daq --daq odp --daq-var mode=sched --daq-var debug -i 0,1
  
This will start Snort in inline mode direcly pairing 0<->1 for traffic forwarding.  Additional debug output will be enabled and it will handle packets using the DPDK-ODP scheduler.

NOTE: This module does not take full advantage of OpenDataPlane as it creates only a single packet processing thread.  This is a fundamental limitation of the current LibDAQ design.
