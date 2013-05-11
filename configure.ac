AC_INIT([AES Pipe], [0.1],
        [Philip Tricca <flihp@twobit.us>],
        [aes-pipe])
AM_INIT_AUTOMAKE
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
PKG_CHECK_MODULES(libssl, [libssl >= 1.0.0])
AC_SUBST(libssl_CFLAGS)
AC_SUBST(libssl_LIBS)
AC_CHECK_HEADERS([openssl/evp.h], , AC_MSG_ERROR([missing openssl/evp.h header]))
AC_CONFIG_FILES([Makefile
        src/Makefile])
AC_OUTPUT
