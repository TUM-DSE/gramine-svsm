# FORK_MARKS=enabled builds the fork-breakdown marks in (meson's fork_marks,
# default disabled; a measurement pair, never the shipped one).
# GLIBC=2.44 builds the 2.44 runtime glibc (meson's glibc_version; the default
# is 2.40). Always passed: --reconfigure keeps an option an earlier setup set,
# so a build after a GLIBC=2.44 one would otherwise stay 2.44.
meson setup --clearcache --reconfigure build/ --buildtype=${MODE} -Dsvsm=enabled -Ddirect=enabled -Dglibc_version=${GLIBC:-2.40} -Dfork_marks=${FORK_MARKS:-disabled} --werror --bindir=$PWD/bin --prefix=$PWD/python-libs
