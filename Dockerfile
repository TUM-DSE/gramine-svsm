# Pinned: mod/2/libpal.so embeds gcc-13 include paths (= 24.04), and
# glibc 2.39 does not build with newer toolchains (gcc 15's kernel
# headers redefine OPEN_TREE_CLONE -> -Werror failure).
FROM ubuntu:24.04
RUN apt-get update
RUN apt-get install -y build-essential \
    autoconf bison gawk nasm ninja-build pkg-config python3 python3-click \
    python3-jinja2 python3-pip python3-pyelftools wget meson vim\
    python3-voluptuous python3-tomli python3-tomli-w inotify-tools gdb\
    cmake libffi-dev libssl-dev libgdbm-dev uuid-dev libsqlite3-dev liblzma-dev libbz2-dev\
    libz-dev libgdbm-dev libgdbm-compat-dev 
ENV PYTHONPATH="/gramine/python-libs/lib/python3.12/site-packages/"
ENV PATH="$PATH:/gramine/bin"
