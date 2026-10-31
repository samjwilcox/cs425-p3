#define _POSIX_C_SOURCE 200809L
#include "../src/lab.h"
#include "harness/unity.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#define CHECK(x) TEST_ASSERT_TRUE_MESSAGE((x), #x)
void setUp(void) {}
void tearDown(void) {}
static uint32_t ip(const char *s) { uint32_t n = 0; CHECK(ip_parse(s,&n)); return n; }
static cidr_t cidr(const char *s) { cidr_t c; CHECK(cidr_parse(s,&c)); return c; }
static void parsers(void) {
    uint32_t n = 123;
    CHECK(!ip_parse(NULL,&n)); CHECK(!ip_parse("1.2.3.4",NULL));
    const char *invalid[] = {"", "1.2.3", "1.2.3.4.5", "1..2.3", "256.1.1.1", "010.0.0.1", "1.2.3.4x", " 1.2.3.4", "1.2.3.4 ", "+1.2.3.4", "-1.2.3.4", "1.2.3.-4", "1.2.3.004", "1.2.3.99999999999", "1.2.3.", "1.2.3a.4", "1.2.3..4"};
    for (size_t i=0;i<sizeof invalid/sizeof *invalid;i++) { CHECK(!ip_parse(invalid[i], &n)); CHECK(n==123); }
    CHECK(ip("0.0.0.0")==0); CHECK(ip("255.255.255.255")==UINT32_MAX);
    CHECK(ip("192.168.1.10")==UINT32_C(0xC0A8010A));
    char buf[IP_STR_LEN]; ip_format(ip("192.168.1.10"),buf); CHECK(!strcmp(buf,"192.168.1.10"));
    cidr_t c={123,23}; CHECK(!cidr_parse(NULL,&c)); CHECK(!cidr_parse("1.2.3.4/24",NULL));
    const char *bad[] = {"", "1.2.3.4", "1.2.3.4/33", "1.2.3.4/024", "1.2.3.4/", "1.2.3/24", "1.2.3.4/-1", "1.2.3.4/+1", "1.2.3.4/2x", "1.2.3.4/2/3", "010.2.3.4/24", "1.2.3.4/999999999", "/24", "1.2.3.4/0 ", "1.2.3.4/000"};
    for(size_t i=0;i<sizeof bad/sizeof *bad;i++) { CHECK(!cidr_parse(bad[i],&c)); CHECK(c.addr==123 && c.prefix==23); }
    c=cidr("1.2.3.4/0"); CHECK(c.prefix==0); c=cidr("1.2.3.4/32"); CHECK(c.prefix==32);
    char cidrbuf[CIDR_STR_LEN]; cidr_format(c,cidrbuf); CHECK(!strcmp(cidrbuf,"1.2.3.4/32"));
    c.prefix=33; cidr_format(c,cidrbuf); CHECK(!strcmp(cidrbuf,"1.2.3.4/32"));
}
static void math_tests(void) {
    CHECK(cidr_mask(0)==0); CHECK(cidr_mask(24)==UINT32_C(0xffffff00)); CHECK(cidr_mask(32)==UINT32_MAX); CHECK(cidr_mask(200)==UINT32_MAX);
    cidr_t c=cidr("132.178.227.11/25");
    CHECK(cidr_network(c)==ip("132.178.227.0")); CHECK(cidr_broadcast(c)==ip("132.178.227.127"));
    CHECK(cidr_first_host(c)==ip("132.178.227.1")); CHECK(cidr_last_host(c)==ip("132.178.227.126"));
    CHECK(cidr_host_count(c)==126); CHECK(cidr_contains(c,ip("132.178.227.50"))); CHECK(!cidr_contains(c,ip("132.178.227.200"))); CHECK(!cidr_is_network(c));
    CHECK(cidr_is_network(cidr("132.178.227.0/25")));
    c=cidr("0.0.0.0/0"); CHECK(cidr_host_count(c)==UINT64_C(4294967294)); CHECK(cidr_contains(c,UINT32_MAX)); CHECK(cidr_first_host(c)==1); CHECK(cidr_last_host(c)==UINT32_MAX-1);
    c=cidr("10.0.0.0/31"); CHECK(cidr_host_count(c)==2); CHECK(cidr_first_host(c)==ip("10.0.0.0")); CHECK(cidr_last_host(c)==ip("10.0.0.1"));
    c=cidr("255.255.255.255/32"); CHECK(cidr_host_count(c)==1); CHECK(cidr_first_host(c)==UINT32_MAX); CHECK(cidr_last_host(c)==UINT32_MAX);
    cidr_t out={44,7}; CHECK(!cidr_subnet(cidr("192.168.1.0/24"),0,0,&out)); CHECK(!cidr_subnet(cidr("192.168.1.0/24"),3,0,&out));
    CHECK(!cidr_subnet(cidr("192.168.1.5/24"),4,0,&out)); CHECK(!cidr_subnet(cidr("192.168.1.0/24"),4,4,&out));
    CHECK(!cidr_subnet(cidr("192.168.1.0/31"),4,0,&out)); CHECK(!cidr_subnet(cidr("192.168.1.0/24"),4,0,NULL));
    CHECK(out.addr==44 && out.prefix==7);
    CHECK(cidr_subnet(cidr("192.168.1.0/24"),4,0,&out)); CHECK(out.addr==ip("192.168.1.0") && out.prefix==26);
    CHECK(cidr_subnet(cidr("192.168.1.0/24"),4,1,&out)); CHECK(out.addr==ip("192.168.1.64"));
    CHECK(cidr_subnet(cidr("192.168.1.0/24"),4,3,&out)); CHECK(out.addr==ip("192.168.1.192"));
    CHECK(cidr_subnet(cidr("0.0.0.0/0"),UINT32_C(2147483648),UINT32_C(2147483647),&out)); CHECK(out.prefix==31 && out.addr==UINT32_MAX-1);
    CHECK(cidr_subnet(cidr("192.168.1.0/24"),1,0,&out)); CHECK(out.prefix==24);
}
static void routes(void) {
    route_t r={0}; CHECK(!route_parse(NULL,&r)); CHECK(!route_parse("default direct eth0",NULL));
    CHECK(route_parse("  default   1.2.3.4   eno1  \n",&r)); CHECK(r.dest.prefix==0 && r.gateway==ip("1.2.3.4") && !strcmp(r.dev,"eno1"));
    CHECK(route_parse("10.1.2.0/24 direct eth2",&r)); CHECK(r.gateway==0 && r.dest.addr==ip("10.1.2.0"));
    const char *bad[]={"", " ", "default", "default direct", "default direct eth0 x", "10.1.2.9/24 direct eth0", "1.2.3.4/33 direct eth0", "default 999.0.0.1 eth0", "default direct abcdefghijklmnop", "default direct ", "default direct a b", "default direct eth0 #comment"};
    route_t before=r;
    for(size_t i=0;i<sizeof bad/sizeof *bad;i++) { CHECK(!route_parse(bad[i],&r)); CHECK(!memcmp(&r,&before,sizeof r)); }
    CHECK(table_count(NULL)==0); table_destroy(NULL); CHECK(table_lookup(NULL,0)==NULL);
    fwd_table_t *t=table_create(); CHECK(t!=NULL); CHECK(table_count(t)==0);
    CHECK(!table_add(NULL,&r)); CHECK(!table_add(t,NULL));
    route_t host={cidr("10.1.2.1/24"),0,"eth0"}; CHECK(!table_add(t,&host));
    const char *entries[]={"default 1.2.3.4 e0", "10.0.0.0/8 10.1.0.1 e1", "10.1.0.0/16 direct e2", "10.1.2.0/24 direct e3", "10.1.2.128/25 10.1.2.1 e4"};
    for(size_t i=0;i<5;i++) { CHECK(route_parse(entries[i],&r)); CHECK(table_add(t,&r)); CHECK(!table_add(t,&r)); }
    CHECK(table_count(t)==5);
    const route_t *found=table_lookup(t,ip("10.1.2.200")); CHECK(found && !strcmp(found->dev,"e4"));
    found=table_lookup(t,ip("10.1.2.5")); CHECK(found && !strcmp(found->dev,"e3"));
    found=table_lookup(t,ip("8.8.8.8")); CHECK(found && !strcmp(found->dev,"e0"));
    fwd_table_t *reverse=table_create(); CHECK(reverse);
    for(int i=4;i>=0;i--) { CHECK(route_parse(entries[i],&r)); CHECK(table_add(reverse,&r)); }
    found=table_lookup(reverse,ip("10.1.2.200")); CHECK(found && !strcmp(found->dev,"e4"));
    table_destroy(t); table_destroy(reverse);
    t=table_create(); CHECK(t);
    CHECK(route_parse("10.0.0.0/8 direct eth0",&r)); CHECK(table_add(t,&r)); CHECK(table_lookup(t,ip("8.8.8.8"))==NULL);
    table_destroy(t);
}
static void load_tests(void) {
    CHECK(!table_load(NULL,NULL,NULL)); size_t bad=99; CHECK(!table_load(NULL,NULL,&bad) && bad==0);
    fwd_table_t *t=table_create(); CHECK(t);
    CHECK(!table_load(t,NULL,&bad) && bad==0);
    FILE *fp=tmpfile(); CHECK(fp);
    fputs("# comment\n\n default 1.2.3.4 e0 # inline\n10.0.0.0/8 direct e1\ninvalid route\n",fp); rewind(fp);
    CHECK(!table_load(t,fp,&bad)); CHECK(bad==5 && table_count(t)==2); fclose(fp);
    fp=tmpfile(); CHECK(fp); fputs("10.0.0.0/8 direct e1\n",fp); rewind(fp);
    CHECK(!table_load(t,fp,&bad)); CHECK(bad==1 && table_count(t)==2); fclose(fp);
    fp=tmpfile(); CHECK(fp); fputs("192.168.0.0/16 direct eth0\n",fp); rewind(fp);
    CHECK(table_load(t,fp,&bad)); CHECK(bad==0 && table_count(t)==3); fclose(fp);
    table_destroy(t);
}
static void test_parsers(void) { parsers(); }
static void test_math(void) { math_tests(); }
static void test_routes(void) { routes(); }
static void test_loading(void) { load_tests(); }
int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_parsers);
    RUN_TEST(test_math);
    RUN_TEST(test_routes);
    RUN_TEST(test_loading);
    return UNITY_END();
}
