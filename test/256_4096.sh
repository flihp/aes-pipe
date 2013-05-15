#!/bin/sh

. ./test-functions

test_run $((256/8)) 4096
exit $?
