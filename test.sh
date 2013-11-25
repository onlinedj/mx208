#!/bin/bash
for i in `seq 1 1000`;do
echo $i
./client 127.0.0.1 &
done
