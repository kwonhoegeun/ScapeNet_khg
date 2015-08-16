#!/bin/sh

mkfifo --mode 0666 .read_sense
mkfifo --mode 0666 .write_sense
mkfifo --mode 0666 .read_face
mkfifo --mode 0666 .write_face

