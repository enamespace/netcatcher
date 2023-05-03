#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/net.h>


#define TASK_COMM_LEN 16
struct net_catcher{
    int recv_total_tcp;
    int recv_total_udp;
};

BPF_HASH(catcher, u32, struct net_catcher, 10240);

int net_catcher_prog(struct pt_regs* ctx, struct socket *sock, struct msghdr *msg, int flags){
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct net_catcher *c;
    struct net_catcher nc = {
        .recv_total_tcp = 0,
        .recv_total_udp = 0,
    };
    c = catcher.lookup_or_try_init(&pid, &nc);
    if (c) {
        struct sock *sk = sock->sk;
        int is_AF_INET = sk && sk->sk_family == AF_INET;
        if (is_AF_INET && sk->sk_protocol == IPPROTO_TCP) {
            c->recv_total_tcp ++;
        }  else if (is_AF_INET && sk->sk_protocol == IPPROTO_UDP) {
            c->recv_total_udp ++;
        }
      
       
    }
    return 0;
}




