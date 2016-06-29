#!/bin/bash
SRC_DIR=$(pwd)
DST_DIR=$SRC_DIR
echo $SRC_DIR
protoc -I=$SRC_DIR --python_out=$DST_DIR $SRC_DIR/proto/safebrowse.proto