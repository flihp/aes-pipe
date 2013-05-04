/*
  AES encryption/decryption program intended for use in shell pipeline.
  gcc -Wall openssl_aes.c -lcrypto

  Philip Tricca <flihp@twobit.us>
*/

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#ifndef TRUE
  #define TRUE 1
#endif

#define USAGE "%s --[encrypt|decrypt] --keyfile /path/to/file.key\n"

typedef struct {
    char* keyfile;
    int encrypt;
    int decrypt;
} args_t;

void
parse_args (int argc, char* argv[], args_t* args)
{
    int ret = 0;
    static struct option options[] = {
        { "encrypt",       no_argument, NULL, 'e' },
        { "decrypt",       no_argument, NULL, 'd' },
        { "keyfile", required_argument, NULL, 'k' },
        {      NULL,                 0, NULL,  0  }
    };
    while ((ret = getopt_long(argc, argv, "edk:", options, NULL)) != -1) {
        switch (ret) {
        case 'e':
            args->encrypt = TRUE;
            break;
        case 'd':
            args->decrypt = TRUE;
            break;
        case 'k':
            args->keyfile = optarg;
            break;
        case '?':
            break;
        default:
            fprintf (stderr, "Unexpected argument: %c", ret);
            break;
        }
    }
}

int
check_sanity (const char* pname, args_t* args)
{
    struct stat keystat = { 0, };
    if (!args->keyfile) {
        fprintf (stderr, USAGE, pname);
        return 1;
    }
    if ((!args->encrypt && !args->decrypt) || 
        (args->encrypt && args->decrypt)) {
        fprintf (stderr, USAGE, pname);
        return 1;
    }
    if (stat (args->keyfile, &keystat) == -1) {
        perror (args->keyfile);
        return 1;
    }
    if (!S_ISREG (keystat.st_mode)) {
        fprintf (stderr, "%s is not a regular file.\n", args->keyfile);
        return 1;
    }
    return 0;
}

size_t
get_key (const char* keyfile, char* keybuf, size_t size)
{
    int fd = 0;
    size_t count = 0, this_read = 0;
    if ((fd = open (keyfile, O_RDONLY)) == -1) {
        fprintf (stderr, "Unable to open keyfile: %s\n", keyfile);
        return -1;
    }
    do {
        this_read = read (fd, keybuf, size - count);
        if (this_read == -1) {
            perror ("read");
            return -1;
        }
        count += this_read;
    } while (this_read != 0 || count == size );
    return count;
}

int
main (int argc, char* argv[])
{
    args_t args = { NULL, TRUE, !TRUE };
    size_t keysize = 0;
    char keybuf[EVP_MAX_KEY_LENGTH] = { 0, };

    parse_args (argc, argv, &args);
    if (check_sanity (argv[0], &args))
        exit (EXIT_FAILURE);
    keysize = get_key (args.keyfile, keybuf, EVP_MAX_KEY_LENGTH);
    if (keysize == -1)
        exit (EXIT_FAILURE);

    fprintf (stderr, "I'll be ");
    if (args.encrypt)
        fprintf (stderr, "encrypting ");
    else
        fprintf (stderr, "decrypting ");

    fprintf (stderr, "with keyfile: %s, of size %d\n", args.keyfile, keysize * 8);

    exit (EXIT_SUCCESS);
}
