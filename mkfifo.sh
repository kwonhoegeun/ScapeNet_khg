#!/bin/sh

if ! [ -d build ] ; then
	mkdir build
fi

mkfifo --mode 0666 ./build/.write_sense
