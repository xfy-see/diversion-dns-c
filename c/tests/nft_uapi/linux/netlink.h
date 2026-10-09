/* TEST ONLY: numeric/layout subset; production uses Linux UAPI. */
#ifndef TEST_NL_UAPI
#define TEST_NL_UAPI
#include <stdint.h>
struct nlmsghdr { uint32_t nlmsg_len; uint16_t nlmsg_type,nlmsg_flags; uint32_t nlmsg_seq,nlmsg_pid; };
struct nlattr { uint16_t nla_len,nla_type; };
struct sockaddr_nl { uint16_t nl_family,nl_pad; uint32_t nl_pid,nl_groups; };
#define AF_NETLINK 16
#define NETLINK_NETFILTER 12
#define SOCK_CLOEXEC 02000000
#define SOCK_NONBLOCK 00004000
#define NLM_F_REQUEST 1
#define NLM_F_ACK 4
#define NLM_F_CREATE 0x400
#define NLA_F_NESTED 0x8000
#endif
