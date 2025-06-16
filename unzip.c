/* unzip.c -- decompress files in gzip or pkzip format.

   Copyright (C) 1997-1999, 2009-2025 Free Software Foundation, Inc.
   Copyright (C) 1992-1993 Jean-loup Gailly

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/*
 * The code in this file is derived from the file funzip.c written
 * and put in the public domain by Mark Adler.
 */

/*
   This version can extract files in gzip or pkzip format.
   For the latter, only the first entry is extracted, and it has to be
   either deflated or stored.
 */

#include <config.h>
#include "tailor.h"
#include "gzip.h"

/* PKZIP header definitions */
#define SPNSIG 0x08074b50L      /* spanned zip file segment marker */
#define ONESIG 0x30304b50L      /* was spanned but re-marked as one segment */
#define Z64SIG 0x06064b50L      /* zip64 end record */
#define ENDSIG 0x06054b50L      /* end record */
#define LOCSIG 0x04034b50L      /* local header */
#define LOCFLG 6                /* offset of bit flag */
#define  CRPFLG 1               /*  bit for encrypted entry */
#define  EXTFLG 8               /*  bit for extended local header */
#define LOCHOW 8                /* offset of compression method */
/* #define LOCTIM 10               UNUSED file mod time */
#define LOCCRC 14               /* offset of crc */
#define LOCSIZ 18               /* offset of compressed size */
#define LOCLEN 22               /* offset of uncompressed length */
#define LOCFIL 26               /* offset of file name field length */
#define LOCEXT 28               /* offset of extra field length */
#define LOCHDR 30               /* size of local header, including sig */
#define EXTHDR 16               /* size of extended local header, inc sig */


/* Globals */

ulg unzip_crc;  /* CRC found by 'unzip'.  */

static int pkzip = 0;      /* set for a pkzip file */
static int ext_header = 0; /* set if extended local header */
static ulg orig_crc;       /* CRC from gzip trailer or zip local header */
static ulg orig_len;       /* uncompressed length from trailer or header */

/* ===========================================================================
 * Check zip file and advance inptr to the start of the compressed data.
 * Get ofname from the local header if necessary.
 * IN is the input file descriptor.
 */
int
check_zipfile (int in)
{
    ulg sig, skip;
    uch *h = inbuf + inptr;
    const char *bad = "not a valid zip file";
    ifd = in;
    do {
        if (insize - inptr < 4)
            break;
        sig = LG(h);
        if (sig == SPNSIG || sig == ONESIG) {
            /* skip spanning signature */
            h += 4;
            inptr += 4;
            if (insize - inptr < 4)
                break;
            sig = LG(h);
        }
        if (sig == ENDSIG || sig == Z64SIG) {
            /* empty zip file */
            bad = "is an empty zip file";
            break;
        }
        if (sig != LOCSIG || insize - inptr < LOCHDR)
            /* not a local header */
            break;
        inptr += LOCHDR;

        /* Get compression method */
        method = SH(h + LOCHOW);
        if (method != STORED && method != DEFLATED) {
            bad = "first entry not deflated or stored -- use unzip";
            break;
        }

        /* Check for encryption */
        if ((h[LOCFLG] & CRPFLG) != 0) {
            bad = "encrypted file -- use unzip";
            break;
        }

        /* Save header information for unzip() */
        ext_header = (h[LOCFLG] & EXTFLG) != 0;
        orig_crc = LG(h + LOCCRC);
        orig_len = LG(h + LOCLEN);
        if (method == STORED && (ext_header || orig_len != LG(h + LOCSIZ)))
            break;
        if (!ext_header && orig_len == 0xffffffff) {
            bad = "Zip64 entry -- not supported, use unzip";
            break;
        }

        /* Get ofname and timestamp from local header (to be done) */

        /* Skip over the file name and extra field (need to loop for the
           SMALL_MEM case) */
        skip = (ulg)SH(h + LOCFIL) + (ulg)SH(h + LOCEXT);
        while (skip > insize - inptr) {
            skip -= insize - inptr;
            fill_inbuf(0);          /* will error out on no more input */
            inptr = 0;
        }
        inptr += skip;

        /* Good local header */
        pkzip = 1;
        bad = NULL;
    } while (0);

    if (bad != NULL) {
        fprintf(stderr, "\n%s: %s: %s\n", program_name, ifname, bad);
        exit_code = ERROR;
        return ERROR;
    }

    return OK;
}

/* ===========================================================================
 * Unzip in to out.  This routine works on both gzip and pkzip files.
 *
 * IN assertions: the buffer inbuf contains already the beginning of
 *   the compressed data, from offsets inptr to insize-1 included.
 *   The magic header has already been checked. The output buffer is cleared.
 *
 * 'in' and 'out' are the input and output file descriptors.
 */
int
unzip (int in, int out)
{
    off_t orig_bytes_out = bytes_out;
    int n;
    uch buf[EXTHDR];        /* extended local header */
    int err = OK;

    ifd = in;
    ofd = out;

    updcrc(NULL, 0);           /* initialize crc */

    /* Decompress */
    if (method == DEFLATED)  {

#ifdef IBM_Z_DFLTCC
        int res = dfltcc_inflate ();
#else
        int res = gzip_inflate ();
#endif

        if (res == 3) {
            xalloc_die ();
        } else if (res != 0) {
            gzip_error ("invalid compressed data--format violated");
        }

    } else if (pkzip && method == STORED) {

        register ulg n = orig_len;
        while (n--) {
            uch c = (uch)get_byte();
            put_ubyte(c);
        }
        flush_window();
    } else {
        gzip_error ("internal error, invalid method");
    }

    /* Get the crc and original length */
    if (!pkzip) {
        /* crc32  (see algorithm.doc)
         * uncompressed input size modulo 2^32
         */
        for (n = 0; n < 8; n++) {
            buf[n] = (uch)get_byte(); /* may cause an error if EOF */
        }
        orig_crc = LG(buf);
        orig_len = LG(buf+4);

    } else if (ext_header) {  /* If extended header, check it */
        /* signature - 4bytes: 0x50 0x4b 0x07 0x08
         * CRC-32 value
         * compressed size 4-bytes
         * uncompressed size 4-bytes
         */
        for (n = 0; n < EXTHDR; n++) {
            buf[n] = (uch)get_byte(); /* may cause an error if EOF */
        }
        orig_crc = LG(buf+4);
        orig_len = LG(buf+12);
    }

    /* Validate decompression */
    if (orig_crc != updcrc(outbuf, 0)) {
        fprintf(stderr, "\n%s: %s: invalid compressed data--crc error\n",
                program_name, ifname);
        err = ERROR;
    }
    if (orig_len != (ulg)((bytes_out - orig_bytes_out) & 0xffffffff)) {
        fprintf(stderr, "\n%s: %s: invalid compressed data--length error\n",
                program_name, ifname);
        err = ERROR;
    }

    /* Check if there are more entries in a pkzip file */
    if (pkzip && inptr + 4 < insize && LG(inbuf+inptr) == LOCSIG) {
        if (to_stdout) {
            WARN((stderr,
                  "%s: %s has more than one entry--rest ignored\n",
                  program_name, ifname));
        } else {
            /* Don't destroy the input zip file */
            fprintf(stderr,
                    "%s: %s has more than one entry -- unchanged\n",
                    program_name, ifname);
            err = ERROR;
        }
    }
    ext_header = pkzip = 0; /* for next file */
    unzip_crc = orig_crc;
    if (err == OK) return OK;
    exit_code = ERROR;
    if (!test) abort_gzip();
    return err;
}
