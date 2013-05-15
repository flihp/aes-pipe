#!/bin/sh

. ./test-functions

test_run $((192/8)) 4096
exit $?
