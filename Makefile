
.PHONY: build run
.DEFAULT_GOAL: build

build:
	./build.sh
	ninja -C build/
	ninja -C build/ install

run:
	gdb -q -x /gramine/python-libs/lib/x86_64-linux-gnu/gramine/svsm/libpal.so  --args /gramine/python-libs/lib/x86_64-linux-gnu/gramine/svsm/libpal.so init helloworld

container:
	docker run --privileged -v ${PWD}:/gramine -w /gramine -it gramine-build-container
