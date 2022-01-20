# libsf 0.1 Beta

This is an attempt to put in working order Mike D. Schiffman  and Shawn Bracken 
libsf, featured on *"Building Open Source Network Security Tools: Components and Techniques"*
by Mike D. Schiffman and published by Wiley with 
[ISBN  978-0-471-20544-9](https://www.wiley.com/en-us/Building+Open+Source+Network+Security+Tools:+Components+and+Techniques-p-9780471205449).

I got back this book from the bookshelf and libsf was the only missing library 
from the ones featured on the book.

I found an old package at [packetfactory](http://packetfactory.openwall.net/projects/libsf/index.html)
as the urls on the book are not working anymore, so I don't really know if it's the
last version released.

The original http://www.packetfactory.net/libsf url is not working as it seems the *packetfactory.com* 
domain have been poached. Point your browser at [openwall](http://packetfactory.openwall.net/) to get 
Mr. Schiffman's libraries in all its glory.

So far the library, samples and tools, compile and run without problems - at last without 
noticeable problems - on a current - 2022 - linux distro.

It uses the old Berkeley Db API and in my system - RedHat Enterprise Linux 8 -
it's provided on the same package that the new API, but the header varies from "db.h"
to "db_185.h". Your mileage may vary. 

I expect it to work as-is on any RedHat family distro
- RedHat
- Fedora
- Oracle Linux
- Rocky Linux
- Centos 8
- Centos Steam
- Scientific Linux

I compiled it with the following required library versions:

* libnet-1.1 (libnet-1.1.6-15.el8.x86_64)
* libdb-5.3 (libdb-5.3.28-42.el8_4.x86_64 but the API reuired is 1.85 I guess)
* libpcap-1.9 (libpcap-1.9.1-5.el8.x86_64)

The autotools script was FUBAR so I swaped the build system to CMake.

It's quite basic and does not check for the requirements, so be sure you
have installed de "devel" packages of all three required libraries.

In the original BUGS file it's stated a single bug "linux no work". I hope it does 
and in my initial tests it seems to do it, but use it at your
how risk.

The license seems to be MIT but it's not explicitly stated. The original license headers should be applied.

The changes in the library are pretty much cosmetic/style to fix compiler
errors, and the build scripts.

To build the library use the commands:

    mkdir build
    cd build
    cmake ..
    make

The tools expect the signatures database to be at /usr/local/share/libsf so make
a symbolic link there to use it. I plan to pass the db as a parameter/env var 
in next refractoring.

To create the db use the tool libsf_import at the build directory passing a signature
file at "import" directory as a parameter.

    cd build
    ./libsf_import ../import/nmap-fp.txt

I have no tested installation so far so install it at your own risk or do it by
hand.

Enjoy !


