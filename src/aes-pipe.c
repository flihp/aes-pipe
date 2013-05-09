/*
  AES encryption/decryption program intended for use in shell pipeline.
  gcc -Wall openssl_aes.c -lcrypto

  Copyright 2013 Philip Tricca <flihp@twobit.us>
*/

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#define USAGE "%s [--verbose] --[encrypt|decrypt] --keyfile /path/to/file.key\n"
#define BUFSIZE 4096

typedef struct {
    char* keyfile;
    bool encrypt;
    bool decrypt;
    bool verbose;
} args_t;

void
parse_args (int argc, char* argv[], args_t* args)
{
    int ret = 0;
    static struct option options[] = {
        { "encrypt",       no_argument, NULL, 'e' },
        { "decrypt",       no_argument, NULL, 'd' },
        { "keyfile", required_argument, NULL, 'k' },
        { "verbose",       no_argument, NULL, 'v' },
        {      NULL,                 0, NULL,  0  }
    };
    while ((ret = getopt_long(argc, argv, "edk:", options, NULL)) != -1) {
        switch (ret) {
        case 'e':
            args->encrypt = true;
            break;
        case 'd':
            args->decrypt = true;
            break;
        case 'k':
            args->keyfile = optarg;
            break;
        case 'v':
            args->verbose = true;
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
    if (args->encrypt == args->decrypt) {
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

ssize_t
fill_buf (char* buf, size_t bufsize, int fd)
{
    ssize_t this_read = 0, count = 0;

    do {
        this_read = read (fd, buf + count, bufsize - count);
        if (this_read == -1) {
            perror ("read");
            return -1;
        }
        count += this_read;
    } while (this_read > 0);

    return count;
}

ssize_t
drain_buf (char* buf, size_t bufsize, int fd)
{
    ssize_t this_write = 0, count = 0;

    do {
        this_write = write (fd, buf + count, bufsize - count);
        if (this_write == -1) {
            perror ("write");
            return -1;
        }
        count += this_write;
        fprintf (stderr, "wrote %d bytes\n", this_write);
    } while (count < bufsize && this_write > 0);

    return count;
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

    return fill_buf (keybuf, size, fd);
}

void
pp_buf (char* buf, size_t bufsize, size_t width, size_t group)
{
    int i = 0;

    for (i = 0; i < bufsize; ++i) {
        printf ("%02x", (unsigned char)*(buf + i));
        if ((i + 1) % group == 0 && i + 1 < bufsize)
            printf (" ");
        if ((i + 1) % width == 0 && i + 1 < bufsize)
            printf ("\n");
    }
    printf ("\n");
}

void
dump_mode (args_t* args, size_t keysize)
{
    fprintf (stderr, "I'll be ");
    if (args->encrypt)
        fprintf (stderr, "encrypting ");
    else
        fprintf (stderr, "decrypting ");

    fprintf (stderr, "with keyfile: %s, of size %d\n", args->keyfile, keysize * 8);
}

int
main (int argc, char* argv[])
{
    args_t args = { NULL, true, false, false };
    size_t keysize = 0;
    ssize_t count_read = 0, count_write = 0;
    char keybuf[EVP_MAX_KEY_LENGTH] = { 0, };
    char databuf[BUFSIZE] = { 0, };

    parse_args (argc, argv, &args);
    if (check_sanity (argv[0], &args))
        exit (EXIT_FAILURE);
    keysize = get_key (args.keyfile, keybuf, EVP_MAX_KEY_LENGTH);
    if (keysize == -1)
        exit (EXIT_FAILURE);
    if (args.verbose)
        dump_mode (&args, keysize);
    do {
        count_read = fill_buf (databuf, BUFSIZE, STDIN_FILENO);
        if (count_read == -1)
            exit (EXIT_FAILURE);
        count_write = drain_buf (databuf, count_read, STDOUT_FILENO);
        if (count_write == -1)
            exit (EXIT_FAILURE);
        if (count_write != count_read) {
            fprintf (stderr, "short write!\n");
            exit (EXIT_FAILURE);
        }
    } while (count_read == BUFSIZE);
    exit (EXIT_SUCCESS);
}
