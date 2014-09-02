/*
 * Copyright (c) 2014      Andreas Schneider <asn@samba.org>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the author nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "config.h"

#include <arpa/inet.h>
#include <sys/types.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <resolv.h>

/* GCC has printf type attribute check. */
#ifdef HAVE_ATTRIBUTE_PRINTF_FORMAT
#define PRINTF_ATTRIBUTE(a,b) __attribute__ ((__format__ (__printf__, a, b)))
#else
#define PRINTF_ATTRIBUTE(a,b)
#endif /* HAVE_ATTRIBUTE_PRINTF_FORMAT */

#ifdef HAVE_DESTRUCTOR_ATTRIBUTE
#define DESTRUCTOR_ATTRIBUTE __attribute__ ((destructor))
#else
#define DESTRUCTOR_ATTRIBUTE
#endif /* HAVE_DESTRUCTOR_ATTRIBUTE */

enum rwrap_dbglvl_e {
	RWRAP_LOG_ERROR = 0,
	RWRAP_LOG_WARN,
	RWRAP_LOG_DEBUG,
	RWRAP_LOG_TRACE
};

#ifdef NDEBUG
# define RWRAP_LOG(...)
#else

static void rwrap_log(enum rwrap_dbglvl_e dbglvl, const char *func, const char *format, ...) PRINTF_ATTRIBUTE(3, 4);
# define RWRAP_LOG(dbglvl, ...) rwrap_log((dbglvl), __func__, __VA_ARGS__)

static void rwrap_log(enum rwrap_dbglvl_e dbglvl,
		      const char *func,
		      const char *format, ...)
{
	char buffer[1024];
	va_list va;
	const char *d;
	unsigned int lvl = 0;
	int pid = getpid();

	d = getenv("RESOLV_WRAPPER_DEBUGLEVEL");
	if (d != NULL) {
		lvl = atoi(d);
	}

	va_start(va, format);
	vsnprintf(buffer, sizeof(buffer), format, va);
	va_end(va);

	if (lvl >= dbglvl) {
		switch (dbglvl) {
			case RWRAP_LOG_ERROR:
				fprintf(stderr,
					"RWRAP_ERROR(%d) - %s: %s\n",
					pid, func, buffer);
				break;
			case RWRAP_LOG_WARN:
				fprintf(stderr,
					"RWRAP_WARN(%d) - %s: %s\n",
					pid, func, buffer);
				break;
			case RWRAP_LOG_DEBUG:
				fprintf(stderr,
					"RWRAP_DEBUG(%d) - %s: %s\n",
					pid, func, buffer);
				break;
			case RWRAP_LOG_TRACE:
				fprintf(stderr,
					"RWRAP_TRACE(%d) - %s: %s\n",
					pid, func, buffer);
				break;
		}
	}
}
#endif /* NDEBUG RWRAP_LOG */

/*********************************************************
 * RWRAP LOADING LIBC FUNCTIONS
 *********************************************************/

#include <dlfcn.h>

struct rwrap_libc_fns {
	int (*libc_res_init)(void);
	int (*libc___res_init)(void);
	int (*libc_res_ninit)(struct __res_state *state);
	int (*libc___res_ninit)(struct __res_state *state);
	void (*libc_res_nclose)(struct __res_state *state);
	void (*libc___res_nclose)(struct __res_state *state);
	void (*libc_res_close)(void);
	void (*libc___res_close)(void);
	int (*libc_res_nquery)(struct __res_state *state,
			       const char *dname,
			       int class,
			       int type,
			       unsigned char *answer,
			       int anslen);
	int (*libc___res_nquery)(struct __res_state *state,
				 const char *dname,
				 int class,
				 int type,
				 unsigned char *answer,
				 int anslen);
	int (*libc_res_nsearch)(struct __res_state *state,
				const char *dname,
				int class,
				int type,
				unsigned char *answer,
				int anslen);
	int (*libc___res_nsearch)(struct __res_state *state,
				  const char *dname,
				  int class,
				  int type,
				  unsigned char *answer,
				  int anslen);
};

struct rwrap {
	void *libc_handle;
	void *libresolv_handle;

	bool initialised;
	bool enabled;

	char *socket_dir;

	struct rwrap_libc_fns fns;
};

static struct rwrap rwrap;

enum rwrap_lib {
    RWRAP_LIBC,
    RWRAP_LIBRESOLV
};

#ifndef NDEBUG
static const char *rwrap_str_lib(enum rwrap_lib lib)
{
	switch (lib) {
	case RWRAP_LIBC:
		return "libc";
	case RWRAP_LIBRESOLV:
		return "libresolv";
	}

	/* Compiler would warn us about unhandled enum value if we get here */
	return "unknown";
}
#endif

static void *rwrap_load_lib_handle(enum rwrap_lib lib)
{
	int flags = RTLD_LAZY;
	void *handle = NULL;
	int i;

#ifdef RTLD_DEEPBIND
	flags |= RTLD_DEEPBIND;
#endif

	switch (lib) {
	case RWRAP_LIBRESOLV:
#ifdef HAVE_LIBRESOLV
		handle = rwrap.libresolv_handle;
		if (handle == NULL) {
			for (i = 10; i >= 0; i--) {
				char soname[256] = {0};

				snprintf(soname, sizeof(soname), "libresolv.so.%d", i);
				handle = dlopen(soname, flags);
				if (handle != NULL) {
					break;
				}
			}

			rwrap.libresolv_handle = handle;
		}
		break;
#endif
		/* FALL TROUGH */
	case RWRAP_LIBC:
		handle = rwrap.libc_handle;
#ifdef LIBC_SO
		if (handle == NULL) {
			handle = dlopen(LIBC_SO, flags);

			rwrap.libc_handle = handle;
		}
#endif
		if (handle == NULL) {
			for (i = 10; i >= 0; i--) {
				char soname[256] = {0};

				snprintf(soname, sizeof(soname), "libc.so.%d", i);
				handle = dlopen(soname, flags);
				if (handle != NULL) {
					break;
				}
			}

			rwrap.libc_handle = handle;
		}
		break;
	}

	if (handle == NULL) {
#ifdef RTLD_NEXT
		handle = rwrap.libc_handle = rwrap.libresolv_handle = RTLD_NEXT;
#else
		RWRAP_LOG(RWRAP_LOG_ERROR,
			  "Failed to dlopen library: %s\n",
			  dlerror());
		exit(-1);
#endif
	}

	return handle;
}

static void *_rwrap_load_lib_function(enum rwrap_lib lib, const char *fn_name)
{
	void *handle;
	void *func;

	handle = rwrap_load_lib_handle(lib);

	func = dlsym(handle, fn_name);
	if (func == NULL) {
		RWRAP_LOG(RWRAP_LOG_ERROR,
				"Failed to find %s: %s\n",
				fn_name, dlerror());
		exit(-1);
	}

	RWRAP_LOG(RWRAP_LOG_TRACE,
			"Loaded %s from %s",
			fn_name, rwrap_str_lib(lib));
	return func;
}

#define rwrap_load_lib_function(lib, fn_name) \
	if (rwrap.fns.libc_##fn_name == NULL) { \
		*(void **) (&rwrap.fns.libc_##fn_name) = \
			_rwrap_load_lib_function(lib, #fn_name); \
	}

/*
 * IMPORTANT
 *
 * Functions especially from libc need to be loaded individually, you can't load
 * all at once or gdb will segfault at startup. The same applies to valgrind and
 * has probably something todo with with the linker.
 * So we need load each function at the point it is called the first time.
 */
#if 0
static int libc_res_init(void)
{
#if defined(HAVE_RES_INIT)
	rwrap_load_lib_function(RWRAP_LIBRESOLV, res_init);

	return rwrap.fns.libc_res_init();
#elif defined(HAVE___RES_INIT)
	rwrap_load_lib_function(RWRAP_LIBRESOLV, __res_init);

	return rwrap.fns.libc___res_init();
#endif
}
#endif

static int libc_res_ninit(struct __res_state *state)
{
#if defined(HAVE_RES_NINIT)
	rwrap_load_lib_function(RWRAP_LIBC, res_ninit);

	return rwrap.fns.libc_res_ninit(state);
#elif defined(HAVE___RES_NINIT)
	rwrap_load_lib_function(RWRAP_LIBC, __res_ninit);

	return rwrap.fns.libc___res_ninit(state);
#else
#error "No res_ninit function"
#endif
}

static void libc_res_nclose(struct __res_state *state)
{
#if defined(HAVE_RES_NCLOSE)
	rwrap_load_lib_function(RWRAP_LIBC, res_nclose);

	rwrap.fns.libc_res_nclose(state);
#elif defined(HAVE___RES_NCLOSE)
	rwrap_load_lib_function(RWRAP_LIBC, __res_nclose);

	rwrap.fns.libc___res_nclose(state);
#else
#error "No res_nclose function"
#endif
}

static int libc_res_nquery(struct __res_state *state,
			   const char *dname,
			   int class,
			   int type,
			   unsigned char *answer,
			   int anslen)
{
#if defined(HAVE_RES_NQUERY)
	rwrap_load_lib_function(RWRAP_LIBRESOLV, res_nquery);

	return rwrap.fns.libc_res_nquery(state,
					 dname,
					 class,
					 type,
					 answer,
					 anslen);
#elif defined(HAVE___RES_NQUERY)
	rwrap_load_lib_function(RWRAP_LIBRESOLV, __res_nquery);

	return rwrap.fns.libc___res_nquery(state,
					   dname,
					   class,
					   type,
					   answer,
					   anslen);
#else
#error "No res_nquery function"
#endif
}

static int libc_res_nsearch(struct __res_state *state,
			    const char *dname,
			    int class,
			    int type,
			    unsigned char *answer,
			    int anslen)
{
#if defined(HAVE_RES_NSEARCH)
	rwrap_load_lib_function(RWRAP_LIBRESOLV, res_nsearch);

	return rwrap.fns.libc_res_nsearch(state,
					  dname,
					  class,
					  type,
					  answer,
					  anslen);
#elif defined(HAVE___RES_NSEARCH)
	rwrap_load_lib_function(RWRAP_LIBRESOLV, __res_nsearch);

	return rwrap.fns.libc___res_nsearch(state,
					    dname,
					    class,
					    type,
					    answer,
					    anslen);
#else
#error "No res_nsearch function"
#endif
}


/****************************************************************************
 *   RES_NINIT
 ***************************************************************************/

static int rwrap_res_ninit(struct __res_state *state)
{
	int rc;

	rc = libc_res_ninit(state);
	if (rc == 0) {
		const char *rwrap_ns_env = getenv("RESOLV_WRAPPER_NAMESERVER");

		if (rwrap_ns_env != NULL) {
			int ok;

			/* Delete name servers */
			state->nscount = 1;
			memset(state->nsaddr_list, 0, sizeof(state->nsaddr_list));

			/* Simply zero the the padding array in the union */
			memset(state->_u.pad, 0, sizeof(state->_u.pad));

			state->nsaddr_list[0] = (struct sockaddr_in) {
				.sin_family = AF_INET,
				.sin_port = htons(53),
			};

			ok = inet_pton(AF_INET, rwrap_ns_env, &state->nsaddr_list[0].sin_addr);
			if (!ok) {
				return -1;
			}

			RWRAP_LOG(RWRAP_LOG_DEBUG,
				  "Using [%s] as new nameserver",
				  rwrap_ns_env);
		}
	}

	return rc;
}

#if defined(HAVE_RES_NINIT)
int res_ninit(struct __res_state *state)
#elif defined(HAVE___RES_NINIT)
int __res_ninit(struct __res_state *state)
#endif
{
	return rwrap_res_ninit(state);
}

/****************************************************************************
 *   RES_INIT
 ***************************************************************************/

static struct __res_state rwrap_res_state;

static int rwrap_res_init(void)
{
	int rc;

	rc = rwrap_res_ninit(&rwrap_res_state);

	return rc;
}

#if defined(HAVE_RES_INIT)
int res_init(void)
#elif defined(HAVE___RES_INIT)
int __res_init(void)
#endif
{
	return rwrap_res_init();
}

/****************************************************************************
 *   RES_NCLOSE
 ***************************************************************************/

static void rwrap_res_nclose(struct __res_state *state)
{
	libc_res_nclose(state);
}

#if defined(HAVE_RES_NCLOSE)
void res_nclose(struct __res_state *state)
#elif defined(HAVE___RES_NCLOSE)
void __res_nclose(struct __res_state *state)
#endif
{
	libc_res_nclose(state);
}

/****************************************************************************
 *   RES_CLOSE
 ***************************************************************************/

static void rwrap_res_close(void)
{
	rwrap_res_nclose(&rwrap_res_state);
}

#if defined(HAVE_RES_CLOSE)
void res_close(void)
#elif defined(HAVE___RES_CLOSE)
void __res_close(void)
#endif
{
	rwrap_res_close();
}

/****************************************************************************
 *   RES_NQUERY
 ***************************************************************************/

static int rwrap_res_nquery(struct __res_state *state,
			    const char *dname,
			    int class,
			    int type,
			    unsigned char *answer,
			    int anslen)
{
	int rc;
#ifndef NDEBUG
	int i;
#endif

	RWRAP_LOG(RWRAP_LOG_TRACE,
		  "Resolve the domain name [%s] - class=%d, type=%d",
		  dname, class, type);
#ifndef NDEBUG
	for (i = 0; i < state->nscount; i++) {
		char ip[INET6_ADDRSTRLEN];

		inet_ntop(AF_INET, &state->nsaddr_list[i].sin_addr, ip, sizeof(ip));
		RWRAP_LOG(RWRAP_LOG_TRACE,
			  "        nameserver: %s",
			  ip);
	}
#endif

	rc = libc_res_nquery(state, dname, class, type, answer, anslen);

	RWRAP_LOG(RWRAP_LOG_TRACE,
		  "The returned response length is: %d",
		  rc);

	return rc;
}

#if defined(HAVE_RES_NQUERY)
int res_nquery(struct __res_state *state,
	       const char *dname,
	       int class,
	       int type,
	       unsigned char *answer,
	       int anslen)
#elif defined(HAVE___RES_NQUERY)
int __res_nquery(struct __res_state *state,
		 const char *dname,
		 int class,
		 int type,
		 unsigned char *answer,
		 int anslen)
#endif
{
	return rwrap_res_nquery(state, dname, class, type, answer, anslen);
}

/****************************************************************************
 *   RES_QUERY
 ***************************************************************************/

static int rwrap_res_query(const char *dname,
			   int class,
			   int type,
			   unsigned char *answer,
			   int anslen)
{
	int rc;

	rc = rwrap_res_ninit(&rwrap_res_state);
	if (rc != 0) {
		return rc;
	}

	rc = rwrap_res_nquery(&rwrap_res_state,
			      dname,
			      class,
			      type,
			      answer,
			      anslen);

	return rc;
}

#if defined(HAVE_RES_QUERY)
int res_query(const char *dname,
	      int class,
	      int type,
	      unsigned char *answer,
	      int anslen)
#elif defined(HAVE___RES_QUERY)
int __res_query(const char *dname,
		int class,
		int type,
		unsigned char *answer,
		int anslen)
#endif
{
	return rwrap_res_query(dname, class, type, answer, anslen);
}

/****************************************************************************
 *   RES_NSEARCH
 ***************************************************************************/

static int rwrap_res_nsearch(struct __res_state *state,
			     const char *dname,
			     int class,
			     int type,
			     unsigned char *answer,
			     int anslen)
{
	int rc;
#ifndef NDEBUG
	int i;
#endif

	RWRAP_LOG(RWRAP_LOG_TRACE,
		  "Resolve the domain name [%s] - class=%d, type=%d",
		  dname, class, type);
#ifndef NDEBUG
	for (i = 0; i < state->nscount; i++) {
		char ip[INET6_ADDRSTRLEN];

		inet_ntop(AF_INET, &state->nsaddr_list[i].sin_addr, ip, sizeof(ip));
		RWRAP_LOG(RWRAP_LOG_TRACE,
			  "        nameserver: %s",
			  ip);
	}
#endif

	rc = libc_res_nsearch(state, dname, class, type, answer, anslen);

	RWRAP_LOG(RWRAP_LOG_TRACE,
		  "The returned response length is: %d",
		  rc);

	return rc;
}

#if defined(HAVE_RES_NSEARCH)
int res_nsearch(struct __res_state *state,
		const char *dname,
		int class,
		int type,
		unsigned char *answer,
		int anslen)
#elif defined(HAVE___RES_NSEARCH)
int __res_nsearch(struct __res_state *state,
		  const char *dname,
		  int class,
		  int type,
		  unsigned char *answer,
		  int anslen)
#endif
{
	return rwrap_res_nsearch(state, dname, class, type, answer, anslen);
}

/****************************************************************************
 *   RES_QUERY
 ***************************************************************************/

static int rwrap_res_search(const char *dname,
			    int class,
			    int type,
			    unsigned char *answer,
			    int anslen)
{
	int rc;

	rc = rwrap_res_ninit(&rwrap_res_state);
	if (rc != 0) {
		return rc;
	}

	rc = rwrap_res_nsearch(&rwrap_res_state,
			       dname,
			       class,
			       type,
			       answer,
			       anslen);

	return rc;
}

#if defined(HAVE_RES_SEARCH)
int res_search(const char *dname,
	       int class,
	       int type,
	       unsigned char *answer,
	       int anslen)
#elif defined(HAVE___RES_SEARCH)
int __res_search(const char *dname,
		 int class,
		 int type,
		 unsigned char *answer,
		 int anslen)
#endif
{
	return rwrap_res_search(dname, class, type, answer, anslen);
}
