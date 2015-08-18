/*
 * Copyright (C) Jakub Hrozek 2014 <jakub.hrozek@posteo.se>
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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "config.h"

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <resolv.h>

#define ANSIZE 256

static void test_res_fake_a_query(void **state)
{
	int rv;
	struct __res_state dnsstate;
	unsigned char answer[ANSIZE];
	char addr[INET_ADDRSTRLEN];
	ns_msg handle;
	ns_rr rr;   /* expanded resource record */

	(void) state; /* unused */

	memset(&dnsstate, 0, sizeof(struct __res_state));
	rv = res_ninit(&dnsstate);
	assert_int_equal(rv, 0);

	rv = res_nquery(&dnsstate, "cwrap.org", ns_c_in, ns_t_a,
			answer, sizeof(answer));
	assert_in_range(rv, 1, 100);

	ns_initparse(answer, sizeof(answer), &handle);
	/* The query must finish w/o an error, have one answer and the answer
	 * must be a parseable RR of type A and have the address that our
	 * fake hosts file contains
	 */
	assert_int_equal(ns_msg_getflag(handle, ns_f_rcode), ns_r_noerror);
	assert_int_equal(ns_msg_count(handle, ns_s_an), 1);
	assert_int_equal(ns_parserr(&handle, ns_s_an, 0, &rr), 0);
	assert_int_equal(ns_rr_type(rr), ns_t_a);
	assert_non_null(inet_ntop(AF_INET, ns_rr_rdata(rr),
			addr, sizeof(addr)));
	assert_string_equal(addr, "127.0.0.21");
}

static void test_res_fake_a_query_case_insensitive(void **state)
{
	int rv;
	struct __res_state dnsstate;
	unsigned char answer[ANSIZE];
	char addr[INET_ADDRSTRLEN];
	ns_msg handle;
	ns_rr rr;   /* expanded resource record */

	(void) state; /* unused */

	memset(&dnsstate, 0, sizeof(struct __res_state));
	rv = res_ninit(&dnsstate);
	assert_int_equal(rv, 0);

	rv = res_nquery(&dnsstate, "CWRAP.ORG", ns_c_in, ns_t_a,
			answer, sizeof(answer));
	assert_in_range(rv, 1, 100);

	ns_initparse(answer, sizeof(answer), &handle);
	/* The query must finish w/o an error, have one answer and the answer
	 * must be a parseable RR of type A and have the address that our
	 * fake hosts file contains. Case does not matter.
	 */
	assert_int_equal(ns_msg_getflag(handle, ns_f_rcode), ns_r_noerror);
	assert_int_equal(ns_msg_count(handle, ns_s_an), 1);
	assert_int_equal(ns_parserr(&handle, ns_s_an, 0, &rr), 0);
	assert_int_equal(ns_rr_type(rr), ns_t_a);
	assert_non_null(inet_ntop(AF_INET, ns_rr_rdata(rr),
			addr, sizeof(addr)));
	assert_string_equal(addr, "127.0.0.21");

	res_nclose(&dnsstate);
}

static void test_res_fake_a_query_trailing_dot(void **state)
{
	int rv;
	struct __res_state dnsstate;
	unsigned char answer[ANSIZE];
	char addr[INET_ADDRSTRLEN];
	ns_msg handle;
	ns_rr rr;   /* expanded resource record */

	(void) state; /* unused */

	memset(&dnsstate, 0, sizeof(struct __res_state));
	rv = res_ninit(&dnsstate);
	assert_int_equal(rv, 0);

	rv = res_nquery(&dnsstate, "cwrap.org.", ns_c_in, ns_t_a,
			answer, ANSIZE);
	assert_in_range(rv, 1, 100);

	ns_initparse(answer, 256, &handle);
	/* The query must finish w/o an error, have one answer and the answer
	 * must be a parseable RR of type A and have the address that our
	 * fake hosts file contains
	 */
	assert_int_equal(ns_msg_getflag(handle, ns_f_rcode), ns_r_noerror);
	assert_int_equal(ns_msg_count(handle, ns_s_an), 1);
	assert_int_equal(ns_parserr(&handle, ns_s_an, 0, &rr), 0);
	assert_int_equal(ns_rr_type(rr), ns_t_a);
	assert_non_null(inet_ntop(AF_INET, ns_rr_rdata(rr), addr, 256));
	assert_string_equal(addr, "127.0.0.21");

	res_nclose(&dnsstate);
}

static void test_res_fake_a_query_notfound(void **state)
{
	int rv;
	struct __res_state dnsstate;
	unsigned char answer[ANSIZE];
	ns_msg handle;

	(void) state; /* unused */

	memset(&dnsstate, 0, sizeof(struct __res_state));
	rv = res_ninit(&dnsstate);
	assert_int_equal(rv, 0);

	rv = res_nquery(&dnsstate, "nosuchentry.org", ns_c_in, ns_t_a,
			answer, sizeof(answer));
	assert_in_range(rv, 1, 100);

	ns_initparse(answer, sizeof(answer), &handle);
	/* The query must finish w/o an error and have no answer */
	assert_int_equal(ns_msg_getflag(handle, ns_f_rcode), ns_r_noerror);
	assert_int_equal(ns_msg_count(handle, ns_s_an), 0);
}

static void test_res_fake_aaaa_query(void **state)
{
	int rv;
	struct __res_state dnsstate;
	unsigned char answer[ANSIZE];
	char addr[INET6_ADDRSTRLEN];
	ns_msg handle;
	ns_rr rr;   /* expanded resource record */

	(void) state; /* unused */

	memset(&dnsstate, 0, sizeof(struct __res_state));
	rv = res_ninit(&dnsstate);
	assert_int_equal(rv, 0);

	rv = res_nquery(&dnsstate, "cwrap6.org", ns_c_in, ns_t_aaaa,
			answer, sizeof(answer));
	assert_in_range(rv, 1, 100);

	ns_initparse(answer, sizeof(answer), &handle);
	/* The query must finish w/o an error, have one answer and the answer
	 * must be a parseable RR of type AAAA and have the address that our
	 * fake hosts file contains
	 */
	assert_int_equal(ns_msg_getflag(handle, ns_f_rcode), ns_r_noerror);
	assert_int_equal(ns_msg_count(handle, ns_s_an), 1);
	assert_int_equal(ns_parserr(&handle, ns_s_an, 0, &rr), 0);
	assert_int_equal(ns_rr_type(rr), ns_t_aaaa);
	assert_non_null(inet_ntop(AF_INET6, ns_rr_rdata(rr),
			addr, sizeof(addr)));
	assert_string_equal(addr, "2a00:1450:4013:c01::63");
}

static void test_res_fake_aaaa_query_notfound(void **state)
{
	int rv;
	struct __res_state dnsstate;
	unsigned char answer[ANSIZE];
	ns_msg handle;

	(void) state; /* unused */

	memset(&dnsstate, 0, sizeof(struct __res_state));
	rv = res_ninit(&dnsstate);
	assert_int_equal(rv, 0);

	rv = res_nquery(&dnsstate, "nosuchentry.org", ns_c_in, ns_t_aaaa,
			answer, sizeof(answer));
	assert_in_range(rv, 1, 100);

	ns_initparse(answer, sizeof(answer), &handle);
	/* The query must finish w/o an error and have no answer */
	assert_int_equal(ns_msg_getflag(handle, ns_f_rcode), ns_r_noerror);
	assert_int_equal(ns_msg_count(handle, ns_s_an), 0);
}

static void test_res_fake_srv_query(void **state)
{
	int rv;
	struct __res_state dnsstate;
	unsigned char answer[ANSIZE];
	ns_msg handle;
	ns_rr rr;   /* expanded resource record */
	const uint8_t *rrdata;
	int prio;
	int weight;
	int port;
	char hostname[MAXDNAME];

	(void) state; /* unused */

	memset(&dnsstate, 0, sizeof(struct __res_state));
	rv = res_ninit(&dnsstate);
	assert_int_equal(rv, 0);

	rv = res_nquery(&dnsstate, "_ldap._tcp.cwrap.org", ns_c_in, ns_t_srv,
			answer, sizeof(answer));
	assert_in_range(rv, 1, 100);

	ns_initparse(answer, sizeof(answer), &handle);

	/*
	 * The query must finish w/o an error, have one answer and the answer
	 * must be a parseable RR of type SRV and have the priority, weight,
	 * port and hostname as in the fake hosts file
	 */
	assert_int_equal(ns_msg_getflag(handle, ns_f_rcode), ns_r_noerror);
	assert_int_equal(ns_msg_count(handle, ns_s_an), 1);
	assert_int_equal(ns_parserr(&handle, ns_s_an, 0, &rr), 0);
	assert_int_equal(ns_rr_type(rr), ns_t_srv);

	rrdata = ns_rr_rdata(rr);
	NS_GET16(prio, rrdata);
	NS_GET16(weight, rrdata);
	NS_GET16(port, rrdata);

	rv = ns_name_uncompress(ns_msg_base(handle),
				ns_msg_end(handle),
				rrdata,
				hostname, MAXDNAME);
	assert_int_not_equal(rv, -1);

	assert_int_equal(prio, 1);
	assert_int_equal(weight, 5);
	assert_int_equal(port, 389);
	assert_string_equal(hostname, "ldap.cwrap.org");
}

/*
 * Test the case of a SRV record query where the
 * fake hosts file entry is minimal in the sense
 * that it omits the priority and weight entries.
 * The server then fills in some default values.
 */
static void test_res_fake_srv_query_minimal(void **state)
{
	int rv;
	struct __res_state dnsstate;
	unsigned char answer[ANSIZE];
	ns_msg handle;
	ns_rr rr;   /* expanded resource record */
	const uint8_t *rrdata;
	int prio;
	int weight;
	int port;
	char hostname[MAXDNAME];
	char addr[INET_ADDRSTRLEN];

	(void) state; /* unused */

	memset(&dnsstate, 0, sizeof(struct __res_state));
	rv = res_ninit(&dnsstate);
	assert_int_equal(rv, 0);

	rv = res_nquery(&dnsstate, "_krb5._tcp.cwrap.org", ns_c_in, ns_t_srv,
			answer, sizeof(answer));
	assert_in_range(rv, 1, 256);

	ns_initparse(answer, sizeof(answer), &handle);

	/*
	 * The query must finish w/o an error, have one answer and the answer
	 * must be a parseable RR of type SRV and have the priority, weight,
	 * port and hostname as in the fake hosts file
	 */
	assert_int_equal(ns_msg_getflag(handle, ns_f_rcode), ns_r_noerror);
	assert_int_equal(ns_msg_count(handle, ns_s_an), 1);
	assert_int_equal(ns_parserr(&handle, ns_s_an, 0, &rr), 0);
	assert_int_equal(ns_rr_type(rr), ns_t_srv);

	rrdata = ns_rr_rdata(rr);
	NS_GET16(prio, rrdata);
	NS_GET16(weight, rrdata);
	NS_GET16(port, rrdata);

	rv = ns_name_uncompress(ns_msg_base(handle),
				ns_msg_end(handle),
				rrdata,
				hostname, MAXDNAME);
	assert_int_not_equal(rv, -1);

	assert_int_equal(prio, 1);
	assert_int_equal(weight, 100);
	assert_int_equal(port, 88);
	assert_string_equal(hostname, "krb5.cwrap.org");

	/* The additional section contains the A record of krb5.cwrap.org */
	assert_int_equal(ns_msg_count(handle, ns_s_ar), 1);
	assert_int_equal(ns_parserr(&handle, ns_s_ar, 0, &rr), 0);
	assert_int_equal(ns_rr_type(rr), ns_t_a);
	assert_string_equal(ns_rr_name(rr), "krb5.cwrap.org");
	assert_non_null(inet_ntop(AF_INET, ns_rr_rdata(rr),
			addr, sizeof(addr)));
	assert_string_equal(addr, "127.0.0.23");
}

static void test_res_fake_soa_query(void **state)
{
	int rv;
	struct __res_state dnsstate;
	unsigned char answer[ANSIZE];
	ns_msg handle;
	ns_rr rr;   /* expanded resource record */
	const uint8_t *rrdata;
	char nameser[MAXDNAME];
	char admin[MAXDNAME];
	int serial;
	int refresh;
	int retry;
	int expire;
	int minimum;

	(void) state; /* unused */

	memset(&dnsstate, 0, sizeof(struct __res_state));
	rv = res_ninit(&dnsstate);
	assert_int_equal(rv, 0);

	rv = res_nquery(&dnsstate, "cwrap.org", ns_c_in, ns_t_soa,
			answer, sizeof(answer));
	assert_in_range(rv, 1, 100);

	ns_initparse(answer, sizeof(answer), &handle);

	/*
	 * The query must finish w/o an error, have one answer and the answer
	 * must be a parseable RR of type SOA and have the data as in the fake
	 * hosts file
	 */
	assert_int_equal(ns_msg_getflag(handle, ns_f_rcode), ns_r_noerror);
	assert_int_equal(ns_msg_count(handle, ns_s_an), 1);
	assert_int_equal(ns_parserr(&handle, ns_s_an, 0, &rr), 0);
	assert_int_equal(ns_rr_type(rr), ns_t_soa);

	rrdata = ns_rr_rdata(rr);

	rv = ns_name_uncompress(ns_msg_base(handle),
				ns_msg_end(handle),
				rrdata,
				nameser, MAXDNAME);
	assert_int_not_equal(rv, -1);
	rrdata += rv;

	rv = ns_name_uncompress(ns_msg_base(handle),
				ns_msg_end(handle),
				rrdata,
				admin, MAXDNAME);
	assert_int_not_equal(rv, -1);
	rrdata += rv;

	NS_GET32(serial, rrdata);
	NS_GET32(refresh, rrdata);
	NS_GET32(retry, rrdata);
	NS_GET32(expire, rrdata);
	NS_GET32(minimum, rrdata);

	assert_string_equal(nameser, "ns1.cwrap.org");
	assert_string_equal(admin, "admin.cwrap.org");
	assert_int_equal(serial, 2014100457);
	assert_int_equal(refresh, 3600);
	assert_int_equal(retry, 300);
	assert_int_equal(expire, 1814400);
	assert_int_equal(minimum, 600);
}

static void test_res_fake_cname_query(void **state)
{
	int rv;
	struct __res_state dnsstate;
	unsigned char answer[ANSIZE];
	ns_msg handle;
	ns_rr rr;   /* expanded resource record */
	const uint8_t *rrdata;
	char cname[MAXDNAME];
	char addr[INET_ADDRSTRLEN];

	(void) state; /* unused */

	memset(&dnsstate, 0, sizeof(struct __res_state));
	rv = res_ninit(&dnsstate);
	assert_int_equal(rv, 0);

	rv = res_nquery(&dnsstate, "rwrap.org", ns_c_in, ns_t_cname,
			answer, sizeof(answer));
	assert_in_range(rv, 1, 256);

	ns_initparse(answer, 256, &handle);
	ns_initparse(answer, sizeof(answer), &handle);

	/*
	 * The query must finish w/o an error, have one answer and the answer
	 * must be a parseable RR of type CNAME and have the cname as in the
	 * fake hosts file
	 */
	assert_int_equal(ns_msg_getflag(handle, ns_f_rcode), ns_r_noerror);
	assert_int_equal(ns_msg_count(handle, ns_s_an), 1);
	assert_int_equal(ns_parserr(&handle, ns_s_an, 0, &rr), 0);
	assert_int_equal(ns_rr_type(rr), ns_t_cname);

	rrdata = ns_rr_rdata(rr);

	rv = ns_name_uncompress(ns_msg_base(handle),
				ns_msg_end(handle),
				rrdata,
				cname, MAXDNAME);
	assert_int_not_equal(rv, -1);

	assert_string_equal(cname, "web.cwrap.org");

	/* The CNAME points to an A record that's present in the additional
	 * section
	 */
	assert_int_equal(ns_msg_count(handle, ns_s_ar), 2);

	assert_int_equal(ns_parserr(&handle, ns_s_ar, 0, &rr), 0);
	assert_int_equal(ns_rr_type(rr), ns_t_cname);
	assert_string_equal(ns_rr_name(rr), "web.cwrap.org");
	rrdata = ns_rr_rdata(rr);

	rv = ns_name_uncompress(ns_msg_base(handle),
				ns_msg_end(handle),
				rrdata,
				cname, MAXDNAME);
	assert_int_not_equal(rv, -1);

	assert_string_equal(cname, "www.cwrap.org");

	assert_int_equal(ns_parserr(&handle, ns_s_ar, 1, &rr), 0);
	assert_int_equal(ns_rr_type(rr), ns_t_a);
	assert_string_equal(ns_rr_name(rr), "www.cwrap.org");
	assert_non_null(inet_ntop(AF_INET, ns_rr_rdata(rr),
			addr, sizeof(addr)));
	assert_string_equal(addr, "127.0.0.22");
}

static void test_res_fake_a_via_cname(void **state)
{
	int rv;
	struct __res_state dnsstate;
	unsigned char answer[ANSIZE];
	ns_msg handle;
	ns_rr rr;   /* expanded resource record */
	const uint8_t *rrdata;
	char cname[MAXDNAME];
	char addr[INET_ADDRSTRLEN];

	(void) state; /* unused */

	memset(&dnsstate, 0, sizeof(struct __res_state));
	rv = res_ninit(&dnsstate);
	assert_int_equal(rv, 0);

	/* Query for A record, but the key is a CNAME. The expected result is
	 * that the whole chain of CNAMEs will be included in the answer section
	 * along with the resulting A
	 */
	rv = res_nquery(&dnsstate, "rwrap.org", ns_c_in, ns_t_a,
			answer, sizeof(answer));
	assert_in_range(rv, 1, 256);

	ns_initparse(answer, sizeof(answer), &handle);

	/*
	 * The query must finish w/o an error, have three answers and the answers
	 * must be a parseable RR of type CNAME and have the cname as in the
	 * fake hosts file
	 */
	assert_int_equal(ns_msg_getflag(handle, ns_f_rcode), ns_r_noerror);
	assert_int_equal(ns_msg_count(handle, ns_s_an), 3);

	assert_int_equal(ns_parserr(&handle, ns_s_an, 0, &rr), 0);
	assert_int_equal(ns_rr_type(rr), ns_t_cname);

	rrdata = ns_rr_rdata(rr);

	rv = ns_name_uncompress(ns_msg_base(handle),
				ns_msg_end(handle),
				rrdata,
				cname, MAXDNAME);
	assert_int_not_equal(rv, -1);

	assert_string_equal(cname, "web.cwrap.org");

	assert_int_equal(ns_parserr(&handle, ns_s_an, 1, &rr), 0);
	assert_int_equal(ns_rr_type(rr), ns_t_cname);

	rrdata = ns_rr_rdata(rr);

	rv = ns_name_uncompress(ns_msg_base(handle),
				ns_msg_end(handle),
				rrdata,
				cname, MAXDNAME);
	assert_int_not_equal(rv, -1);

	assert_string_equal(cname, "www.cwrap.org");

	assert_int_equal(ns_parserr(&handle, ns_s_an, 2, &rr), 0);
	assert_int_equal(ns_rr_type(rr), ns_t_a);
	assert_string_equal(ns_rr_name(rr), "www.cwrap.org");
	assert_non_null(inet_ntop(AF_INET, ns_rr_rdata(rr),
			addr, sizeof(addr)));
	assert_string_equal(addr, "127.0.0.22");
}

int main(void)
{
	int rc;

	const struct CMUnitTest fake_tests[] = {
		cmocka_unit_test(test_res_fake_a_query),
		cmocka_unit_test(test_res_fake_a_query_case_insensitive),
		cmocka_unit_test(test_res_fake_a_query_trailing_dot),
		cmocka_unit_test(test_res_fake_a_query_notfound),
		cmocka_unit_test(test_res_fake_aaaa_query),
		cmocka_unit_test(test_res_fake_aaaa_query_notfound),
		cmocka_unit_test(test_res_fake_srv_query),
		cmocka_unit_test(test_res_fake_srv_query_minimal),
		cmocka_unit_test(test_res_fake_soa_query),
		cmocka_unit_test(test_res_fake_cname_query),
		cmocka_unit_test(test_res_fake_a_via_cname),
	};

	rc = cmocka_run_group_tests(fake_tests, NULL, NULL);

	return rc;
}
