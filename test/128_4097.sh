#!/bin/sh

. ./test-functions

test_run $((128/8)) 4097
exit $?
