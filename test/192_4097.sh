#!/bin/sh

. ./test-functions

test_run $((192/8)) 4097
exit $?
