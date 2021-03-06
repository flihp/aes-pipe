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
#define INBUFSIZE 4096

bool verbose = false;

typedef struct {
    char* keyfile;
    bool encrypt;
    bool decrypt;
    bool verbose;
} args_t;

typedef struct {
    size_t buf_size;
    char* out_buf;
    char* in_buf;
    EVP_CIPHER_CTX ctx;
    char keybuf [EVP_MAX_KEY_LENGTH];
    ssize_t keysize;
    char ivbuf [EVP_MAX_KEY_LENGTH];
    ssize_t ivsize;
} crypt_data_t;

typedef int (*crypt_init_t)(EVP_CIPHER_CTX*, const EVP_CIPHER*, ENGINE*, const unsigned char*, const unsigned char*);
typedef int (*crypt_update_t)(EVP_CIPHER_CTX*, unsigned char*, int*, const unsigned char*, int);
typedef int (*crypt_final_t)(EVP_CIPHER_CTX*, unsigned char*, int *);

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

ssize_t
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
pp_buf (FILE* fp, char* buf, size_t bufsize, size_t width, size_t group)
{
    int i = 0;

    for (i = 0; i < bufsize; ++i) {
        fprintf (fp, "%02x", (unsigned char)*(buf + i));
        if ((i + 1) % group == 0 && i + 1 < bufsize)
            fprintf (fp, " ");
        if ((i + 1) % width == 0 && i + 1 < bufsize)
            fprintf (fp, "\n");
    }
    fprintf (fp, "\n");
}

void
dump_args (args_t* args)
{
    fprintf (stderr, "I'll be ");
    if (args->encrypt)
        fprintf (stderr, "encrypting ");
    else
        fprintf (stderr, "decrypting ");

    fprintf (stderr, "with keyfile: %s\n", args->keyfile);
}

ssize_t
iv_read (crypt_data_t* crypt_data, int fd_in)
{
    ssize_t count = 0;

    count = fill_buf (crypt_data->ivbuf, crypt_data->ivsize, fd_in);
    if (count == -1)
        return -1;
    if (count != crypt_data->ivsize) {
        fprintf (stderr, "Error: Unable to read IV from input stream.\n");
        return -1;
    }

    return crypt_data->ivsize;
}

ssize_t
iv_write (crypt_data_t* crypt_data, int fd_out)
{
    int fd = 0, count = 0;

    if ((fd = open (RANDFILE, O_RDONLY)) == -1) {
        fprintf (stderr, "Unable to open file %s\n", RANDFILE);
        return -1;
    }

    crypt_data->ivsize = fill_buf (crypt_data->ivbuf, crypt_data->ivsize, fd);
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

ssize_t
proc_loop (crypt_data_t* crypt_data,
           crypt_update_t crypt_update,
           crypt_final_t crypt_final)
{
    ssize_t count_crypt = 0, count_read = 0, count_write = 0;
    int tmp = 0;

    do {
        count_crypt = 0;
        count_read = fill_buf (crypt_data->in_buf,
                               crypt_data->buf_size,
                               STDIN_FILENO);
        if (count_read == -1)
            exit (EXIT_FAILURE);
        if (verbose)
            fprintf (stderr, "crypting %d bytes\n", count_read);
        if (count_read > 0) {
            if (!crypt_update (&crypt_data->ctx, crypt_data->out_buf, &tmp, crypt_data->in_buf, count_read)) {
                fprintf (stderr, "crypt_update failed\n");
                return -1;
            }
            count_crypt += tmp;
        }
        if (count_read < crypt_data->buf_size) {
            if (!crypt_final (&crypt_data->ctx, &crypt_data->out_buf[count_crypt], &tmp)) {
                fprintf (stderr, "crypt_final failed\n");
                return -1;
            }
            count_crypt += tmp;
        }
        if (verbose)
            fprintf (stderr, "crypted %d bytes\n");
        count_write += drain_buf (crypt_data->out_buf, count_crypt, STDOUT_FILENO);
        if (count_write == -1)
            exit (EXIT_FAILURE);
        if (verbose)
            fprintf (stderr, "wrote %d bytes\n", count_write);
        if (count_write < count_crypt) {
            fprintf (stderr, "short write!\n");
            exit (EXIT_FAILURE);
        }
    } while (count_read == crypt_data->buf_size);

    return count_write;
}

int
aes_init (crypt_data_t* crypt_data, crypt_init_t crypt_init)
{
    const EVP_CIPHER* cipher = 0;

    switch (crypt_data->keysize) {
    case 16:
        cipher = EVP_aes_128_cbc ();
        break;
    case 24:
        cipher = EVP_aes_192_cbc ();
        break;
    case 32:
        cipher = EVP_aes_256_cbc ();
        break;
    default:
        fprintf (stderr, "Invalid key size.\n");
        return -1;
    }

    EVP_CIPHER_CTX_init (&crypt_data->ctx);
    if (!crypt_init (&crypt_data->ctx,
                     cipher,
                     NULL,
                     crypt_data->keybuf,
                     crypt_data->ivbuf)) {
        fprintf (stderr, "OpenSSL initialization failed.\n");
        return 1;
    }
    if (verbose) {
        fprintf (stderr,
                 "EVP Initialized\n  Algorithm: %s\n",
                 EVP_CIPHER_name (EVP_CIPHER_CTX_cipher (&crypt_data->ctx)));
        fprintf (stderr, "  IV:  ");
        pp_buf (stderr, crypt_data->ivbuf, crypt_data->ivsize, 16, 2);
        fprintf (stderr, "  Key: ");
        pp_buf (stderr, crypt_data->keybuf, crypt_data->keysize, 16, 2);
    }
    crypt_data->buf_size = INBUFSIZE;
    crypt_data->out_buf =
        (char*)malloc (crypt_data->buf_size +
                       EVP_CIPHER_CTX_block_size (&crypt_data->ctx));
    crypt_data->in_buf = (char*)malloc (crypt_data->buf_size);
    if (!crypt_data->out_buf || !crypt_data->in_buf) {
        fprintf (stderr, "Unable to allocate memory.\n");
        return 1;
    }
    return 0;
}

int
main (int argc, char* argv[])
{
    args_t args = { 0, };
    crypt_data_t crypt_data = { 0, };
    ssize_t count = 0;
    crypt_init_t init_func = NULL;
    crypt_update_t update_func = NULL;
    crypt_final_t final_func = NULL;

    parse_args (argc, argv, &args);
    if (check_sanity (argv[0], &args))
        exit (EXIT_FAILURE);
    /*  set global flag  */
    verbose = args.verbose;
    if (verbose)
        dump_args (&args);

    crypt_data.keysize = get_key (args.keyfile, crypt_data.keybuf, EVP_MAX_KEY_LENGTH);
    if (crypt_data.keysize == -1)
        exit (EXIT_FAILURE);
    crypt_data.ivsize = crypt_data.keysize;

    if (args.encrypt) {
        crypt_data.ivsize = iv_write (&crypt_data, STDOUT_FILENO);
        if (crypt_data.ivsize == -1)
            exit (EXIT_FAILURE);
        init_func = &EVP_EncryptInit_ex;
        update_func = &EVP_EncryptUpdate;
        final_func = &EVP_EncryptFinal_ex;
    }
    if (args.decrypt) {
        crypt_data.ivsize = iv_read (&crypt_data, STDIN_FILENO);
        if (crypt_data.ivsize == -1)
            exit (EXIT_FAILURE);
        init_func = &EVP_DecryptInit_ex;
        update_func = &EVP_DecryptUpdate;
        final_func = &EVP_DecryptFinal_ex;
    }
    count = aes_init (&crypt_data, init_func);
    if (count == -1)
        exit (EXIT_FAILURE);
    count = proc_loop (&crypt_data, update_func, final_func);
    if (count == -1)
        exit (EXIT_FAILURE);

    if (verbose)
        fprintf (stderr,
                 "successfully %s %d bytes of data\n",
                 args.encrypt ? "encrypted" : "decrypted",
                 count);

    exit (EXIT_SUCCESS);
}
