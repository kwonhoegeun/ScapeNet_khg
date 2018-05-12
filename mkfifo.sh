#!/bin/sh

if [ ! -d build ]; then
	mkdir build
fi

if [ ! -p ./build/.write_sense ]; then
	echo "Created fifo file into './build'"
	mkfifo --mode 0666 ./build/.write_sense
fi
