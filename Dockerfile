FROM ubuntu:latest
RUN apt-get update
RUN apt-get install -y build-essential \
    autoconf bison gawk nasm ninja-build pkg-config python3 python3-click \
    python3-jinja2 python3-pip python3-pyelftools wget meson vim python3-voluptuous python3-tomli python3-tomli-w inotify-tools gdb
COPY . gramine-svsm/
WORKDIR gramine-svsm
RUN ./build.sh
RUN ninja -C build/
RUN ninja -C build/ install
