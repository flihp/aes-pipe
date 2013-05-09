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

#define RANDFILE "/dev/urandom"
#define USAGE "%s [--verbose] --[encrypt|decrypt] --keyfile /path/to/file.key\n"
#define BUFSIZE 4096
#define IVSIZE 1024

typedef struct {
    char* keyfile;
    bool encrypt;
    bool decrypt;
    bool verbose;
} args_t;

typedef struct {
    char keybuf [EVP_MAX_KEY_LENGTH];
    ssize_t keysize;
    char ivbuf [IVSIZE];
    ssize_t ivsize;
} crypt_data_t;

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
dump_mode (args_t* args, crypt_data_t* data)
{
    fprintf (stderr, "I'll be ");
    if (args->encrypt)
        fprintf (stderr, "encrypting ");
    else
        fprintf (stderr, "decrypting ");

    fprintf (stderr, "with keyfile: %s, of size %d and %d byte IV\n", args->keyfile, data->keysize * 8, data->ivsize);
}

ssize_t
iv_write (crypt_data_t* crypt_data, int fd_out)
{
    int fd = 0, count = 0;

    if ((fd = open (RANDFILE, O_RDONLY)) == -1) {
        fprintf (stderr, "Unable to open file %s\n", RANDFILE);
        return -1;
    }

    crypt_data->ivsize = fill_buf (crypt_data->ivbuf, IVSIZE, fd);
    if (crypt_data->ivsize == -1)
        return -1;
    count = drain_buf (crypt_data->ivbuf, crypt_data->ivsize, fd_out);
    if (count == -1)
        return -1;
    if (count != crypt_data->ivsize) {
        fprintf (stderr, "Error: Didn't write full IV.");
        return -1;
    }
    return crypt_data->ivsize;
}

int
main (int argc, char* argv[])
{
    args_t args = { 0, };
    crypt_data_t crypt_data = { 0, };
    ssize_t count_read = 0, count_write = 0;
    char databuf[BUFSIZE] = { 0, };

    parse_args (argc, argv, &args);
    if (check_sanity (argv[0], &args))
        exit (EXIT_FAILURE);
    crypt_data.keysize = get_key (args.keyfile, crypt_data.keybuf, EVP_MAX_KEY_LENGTH);
    if (crypt_data.keysize == -1)
        exit (EXIT_FAILURE);
    if (args.encrypt) {
        crypt_data.ivsize = iv_write (&crypt_data, STDOUT_FILENO);
        if (crypt_data.ivsize == -1)
            exit (EXIT_FAILURE);
    }
    if (args.verbose)
        dump_mode (&args, &crypt_data);
    do {
        count_read = fill_buf (databuf, BUFSIZE, STDIN_FILENO);
        if (count_read == -1)
            exit (EXIT_FAILURE);
        if (args.verbose)
            fprintf (stderr, "read %d bytes\n", count_read);
        count_write = drain_buf (databuf, count_read, STDOUT_FILENO);
        if (count_write == -1)
            exit (EXIT_FAILURE);
        if (args.verbose)
            fprintf (stderr, "wrote %d bytes\n", count_write);
        if (count_write != count_read) {
            fprintf (stderr, "short write!\n");
            exit (EXIT_FAILURE);
        }
    } while (count_read == BUFSIZE);
    exit (EXIT_SUCCESS);
}
