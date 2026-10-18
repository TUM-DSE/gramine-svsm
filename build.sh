meson setup --clearcache --reconfigure build/ --buildtype=${MODE} -Dsvsm=enabled -Ddirect=enabled -Dsvsm_test_hooks=${SVSM_TEST_HOOKS:-disabled} --werror --bindir=$PWD/bin --prefix=$PWD/python-libs
