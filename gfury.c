#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_dl.h>
#include <libproc.h>
#include <sys/sysctl.h>

#define TTL_TARGET 65
#define NEW_TTL 64
#define BUFFER_SIZE 65535
#define MAX_TRACKED_PIDS 4096
#define IPTOS_LOWDELAY 0x10

volatile sig_atomic_t keep_running = 1;
pcap_t *handle_global = NULL;
int main_pid = -1;
int tracked_pids[MAX_TRACKED_PIDS];
int pid_count = 0;
int raw_sock = -1;
unsigned char my_mac[ETHER_ADDR_LEN];

unsigned short ip_checksum(unsigned short *ptr, int nbytes) {
    long sum;
    unsigned short oddbyte;
    unsigned short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char*)&oddbyte) = *(u_char*)ptr;
        sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (unsigned short)~sum;
    return answer;
}

void handle_sigint(int sig) {
    keep_running = 0;
    if (handle_global != NULL) {
        pcap_breakloop(handle_global);
    }
}

char* get_default_interface() {
    struct ifaddrs *ifaddr, *ifa;
    static char dev_name[IF_NAMESIZE] = "en0";

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return dev_name;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET && strcmp(ifa->ifa_name, "lo0") != 0) {
            strncpy(dev_name, ifa->ifa_name, IF_NAMESIZE);
            break;
        }
    }

    freeifaddrs(ifaddr);
    return dev_name;
}

int get_mac_address(char *ifname, unsigned char *mac_out) {
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_dl *sdl;

    if (getifaddrs(&ifap) == 0) {
        for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr->sa_family == AF_LINK && strcmp(ifa->ifa_name, ifname) == 0) {
                sdl = (struct sockaddr_dl *)ifa->ifa_addr;
                memcpy(mac_out, LLADDR(sdl), sdl->sdl_alen);
                freeifaddrs(ifap);
                return 0;
            }
        }
        freeifaddrs(ifap);
    }
    return -1;
}

int get_pid_from_path(const char *app_path) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t len;
    struct kinfo_proc *procs = NULL;
    int proc_count = 0;

    if (sysctl(mib, 4, NULL, &len, NULL, 0) < 0) return -1;

    procs = malloc(len);
    if (!procs || sysctl(mib, 4, procs, &len, NULL, 0) < 0) {
        free(procs);
        return -1;
    }

    proc_count = len / sizeof(struct kinfo_proc);
    for (int i = 0; i < proc_count; i++) {
        char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
        if (proc_pidpath(procs[i].kp_proc.p_pid, pathbuf, sizeof(pathbuf)) > 0 && strstr(pathbuf, app_path) != NULL) {
            int pid = procs[i].kp_proc.p_pid;
            free(procs);
            return pid;
        }
    }

    free(procs);
    return -1;
}

void track_child_pids(int parent_pid) {
    pid_t children[MAX_TRACKED_PIDS];
    int count = proc_listchildpids(parent_pid, children, sizeof(children) / sizeof(children[0]));

    if (count < 0) return;

    for (int i = 0; i < count && pid_count < MAX_TRACKED_PIDS; i++) {
        if (children[i] != 0) {
            tracked_pids[pid_count++] = children[i];
        }
    }
}

int are_tracked_pids_running() {
    for (int i = 0; i < pid_count; i++) {
        if (kill(tracked_pids[i], 0) == 0) {
            return 1;
        }
    }
    return 0;
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip)) return;

    struct ether_header *eth_header = (struct ether_header *)packet;

    if (memcmp(eth_header->ether_shost, my_mac, ETHER_ADDR_LEN) == 0) {
        return;
    }

    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) return;

    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    
    if (ip_header->ip_p == IPPROTO_TCP || ip_header->ip_p == IPPROTO_UDP) {
        int ttl = ip_header->ip_ttl;

        if (ttl == TTL_TARGET) {
            ip_header->ip_ttl = NEW_TTL;
            
            int tos = IPTOS_LOWDELAY;
            setsockopt(raw_sock, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));

            ip_header->ip_sum = 0;
            ip_header->ip_sum = ip_checksum((unsigned short *)ip_header, ip_header->ip_hl * 4);

            struct sockaddr_in dest_addr;
            memset(&dest_addr, 0, sizeof(dest_addr));
            dest_addr.sin_family = AF_INET;
            dest_addr.sin_addr = ip_header->ip_dst;

            ssize_t sent = sendto(raw_sock, packet + sizeof(struct ether_header), 
                                ntohs(ip_header->ip_len), 0, 
                                (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            
            if (sent < 0) {
                // Silently ignore errors to avoid log spam
            }
        }
    }
}

void *pid_monitor(void *arg) {
    while (keep_running) {
        if (get_pid_from_path((const char *)arg) == -1 && !are_tracked_pids_running()) {
            printf("Parent application or child processes closed. Exiting...\n");
            keep_running = 0;
            pcap_breakloop(handle_global);
            break;
        }

        pid_count = 0;
        track_child_pids(main_pid);
        
        sleep(1);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

    if (argc < 2) {
        printf("Usage: %s <application_path>\n", argv[0]);
        return 1;
    }

    main_pid = get_pid_from_path(argv[1]);
    if (main_pid == -1) {
        printf("Application not found or cannot be tracked: %s\n", argv[1]);
        return 1;
    }
    printf("Target Application: %s, PID: %d\n", argv[1], main_pid);

    track_child_pids(main_pid);

    char *dev = get_default_interface();
    printf("Using Network Interface: %s\n", dev);

    if (get_mac_address(dev, my_mac) != 0) {
        fprintf(stderr, "Failed to get MAC address for %s\n", dev);
        return 1;
    }

    raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sock < 0) {
        perror("Failed to open raw socket (Run with sudo)");
        return 1;
    }
    
    int one = 1;
    if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("Failed to set IP_HDRINCL");
        close(raw_sock);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    handle_global = pcap_open_live(dev, BUFFER_SIZE, 1, 1000, errbuf);
    if (handle_global == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        close(raw_sock);
        return 2;
    }
    printf("Listening started... Packets with TTL %d will be modified to %d.\n", TTL_TARGET, NEW_TTL);

    pthread_t monitor_thread;
    if (pthread_create(&monitor_thread, NULL, pid_monitor, (void *)argv[1]) != 0) {
        perror("Failed to create PID monitor thread");
        pcap_close(handle_global);
        close(raw_sock);
        return 3;
    }

    if (pcap_loop(handle_global, 0, packet_handler, NULL) < 0 && keep_running) {
        fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(handle_global));
    }

    pthread_join(monitor_thread, NULL);
    pcap_close(handle_global);
    close(raw_sock);
    printf("Program terminated successfully.\n");
    return 0;
}
