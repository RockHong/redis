/*
 * Copyright (c) 2009-2012, Salvatore Sanfilippo <antirez at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _REDIS_FMACRO_H
#define _REDIS_FMACRO_H

/* hong: why need feature test macros? (tlpi p61 s3.6)
 * different OS/system implement system calls according to different standard, like Single UNIX Specification,
 * BSD and system V. glibc(GNU implementation of Standard C library) need to use system calls to 
 * implement standard c library calls, like using open() to implement fopen(). therefor, glibc defines these
 * feature test macros to determine which flavor system calls to use to implement c lib calls. */

/* hong: http://www.gnu.org/software/libc/manual/html_node/Feature-Test-Macros.html
 * If you define this macro, functionality derived from 4.3 BSD Unix is included as well as the ISO C, POSIX.1, and POSIX.2 material.
 * see also in tlpi */
#define _BSD_SOURCE

/* hong: __linux__ will be defined by gcc on linux.
 * want to know all default macros?
 * $ touch dummy.hxx
 * $ cpp -dM ./dummy.hxx
 * flag -dM will list predefined macros
 * http://stackoverflow.com/questions/2565979/macros-for-gcc-g-to-differentiate-linux-and-mac-osx
 */
#if defined(__linux__)
/* hong: If you define this macro, everything is included: ISO C89, ISO C99, POSIX.1, POSIX.2, BSD, SVID, X/Open, LFS, and GNU extensions. 
 * In the cases where POSIX.1 conflicts with BSD, the POSIX definitions take precedence.
 *
 * tlpi p62: If defined (with any value), expose all of the definitions provided by setting
 * all of the preceding macros(_BSD_SOURCE, _SVID_SOURCE), as well as various GNU extensions. */
#define _GNU_SOURCE
#endif

#if defined(__linux__) || defined(__OpenBSD__)
/* hong: tlpi p62, If defined (with any value), expose POSIX.1, POSIX.2, and X/Open
 * (XPG4) definitions. ... Setting to 700 or greater also exposes SUSv4 XSI extensions. */
#define _XOPEN_SOURCE 700
/*
 * On NetBSD, _XOPEN_SOURCE undefines _NETBSD_SOURCE and
 * thus hides inet_aton etc.
 */
#elif !defined(__NetBSD__)
#define _XOPEN_SOURCE
#endif

/* hong: for large files,
 * http://stackoverflow.com/questions/14184031/what-is-the-difference-between-largefile-source-and-file-offset-bits-64
 * This macro was introduced as part of the Large File Support extension (LFS).
 */
#define _LARGEFILE_SOURCE
/* hong: for Large File Support. tlpi p106 */
#define _FILE_OFFSET_BITS 64

#endif
