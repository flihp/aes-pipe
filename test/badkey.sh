#!/bin/sh

. ./test-functions

# use an invalid key size
test_run 15 1
exit $?
