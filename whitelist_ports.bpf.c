#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

const volatile int pid_target = 0;

SEC("kprobe/inet_csk_get_port")
int prevent_unauthorized_login(struct pt_regs *ctx) {
    
    	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
		u16 port;
		bpf_probe_read_kernel(&port, sizeof(port), &sk->__sk_common.skc_num);
        BPF_CORE_READ(sk, __sk_common.skc_family);
        bpf_printk("Checking port: %u\n", port);

    u16 whitelist_ports[] = {8080,12345,8081};

    int is_whitelisted = 0;
    for (int i = 0; i < sizeof(whitelist_ports) / sizeof(whitelist_ports[0]); i++) {
        if (port == whitelist_ports[i]) {
            is_whitelisted = whitelist_ports[i];
            break;
        }
    }
     if(is_whitelisted == port){
        if (port == 0){
            return 0;
          }
          else{
            bpf_printk("Whitelisted Connection Port : %u ",port);
          }
     }
     else {
        bpf_send_signal(15);
        }


    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
