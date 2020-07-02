#!/bin/sh
set +e

g++ -O3 -Wall -Wextra -Wno-unused-parameter \
    -ggdb -g -pthread \
    -std=c++11 -o recvtest main.cc