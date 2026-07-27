FROM ubuntu:latest # image id b1d9df8ab815 known working
RUN apt update
RUN apt-get install -y build-essential \
    autoconf bison gawk nasm ninja-build pkg-config python3 python3-click \
    python3-jinja2 python3-jsonschema python3-pip python3-pyelftools wget meson vim\
    python3-voluptuous python3-tomli python3-tomli-w inotify-tools gdb\
    cmake libffi-dev libssl-dev libgdbm-dev uuid-dev libsqlite3-dev liblzma-dev libbz2-dev\
    libz-dev libgdbm-dev libgdbm-compat-dev 
ENV PYTHONPATH="/gramine/python-libs/lib/python3.12/site-packages/"
ENV PATH="$PATH:/gramine/bin"
