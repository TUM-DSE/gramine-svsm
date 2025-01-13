meson setup --clearcache --reconfigure build/ --buildtype=${MODE} -Dsvsm=enabled -Ddirect=enabled --werror --bindir=$PWD/bin --prefix=$PWD/python-libs
