#!/bin/bash

for i in src/*.cc
do
	diff $i ../tupleroute_exh/$i
done;