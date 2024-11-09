#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
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
#include <libproc.h>
#include <sys/sysctl.h>

#define TTL_TARGET 65
#define NEW_TTL 64
#define HOP_LIMIT_TARGET 65
#define NEW_HOP_LIMIT 64
#define BUFFER_SIZE 65535
#define MAX_TRACKED_PIDS 4096
#define IPTOS_LOWDELAY 0x10       // QoS - Düşük Gecikme etiketi
#define IPV6_TCLASS_LOWDELAY 0x10 // IPv6 için QoS etiketi

volatile sig_atomic_t keep_running = 1;
pcap_t *handle_global = NULL;
int main_pid = -1;
int tracked_pids[MAX_TRACKED_PIDS];
int pid_count = 0;

void handle_sigint(int sig) {
    keep_running = 0;
    if (handle_global != NULL) {
        pcap_breakloop(handle_global);
    }
}

// Varsayılan ağ arayüzünü seçme
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

// Uygulama yolundan ana uygulamanın PID'sini alır
int get_pid_from_path(const char *app_path) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t len;
    struct kinfo_proc *procs = NULL;
    int proc_count = 0;

    if (sysctl(mib, 4, NULL, &len, NULL, 0) < 0) {
        perror("sysctl");
        return -1;
    }

    procs = malloc(len);
    if (!procs || sysctl(mib, 4, procs, &len, NULL, 0) < 0) {
        perror("malloc/sysctl");
        free(procs);
        return -1;
    }

    proc_count = len / sizeof(struct kinfo_proc);
    for (int i = 0; i < proc_count; i++) {
        char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
        if (proc_pidpath(procs[i].kp_proc.p_pid, pathbuf, sizeof(pathbuf)) > 0 && strstr(pathbuf, app_path) != NULL) {
            free(procs);
            return procs[i].kp_proc.p_pid;
        }
    }

    free(procs);
    return -1;
}

// Belirli bir uygulamanın tüm child PID'lerini izleme listesine ekler
void track_child_pids(int parent_pid) {
    pid_t children[MAX_TRACKED_PIDS];
    int count = proc_listchildpids(parent_pid, children, sizeof(children) / sizeof(children[0]));

    if (count < 0) {
        perror("proc_listchildpids");
        return;
    }

    for (int i = 0; i < count && pid_count < MAX_TRACKED_PIDS; i++) {
        if (children[i] != 0) {
            tracked_pids[pid_count++] = children[i];
        }
    }
}

// Ana uygulama ve child process’lerin açık olup olmadığını kontrol eden fonksiyon
int are_tracked_pids_running() {
    for (int i = 0; i < pid_count; i++) {
        if (kill(tracked_pids[i], 0) == 0) { // Process hala çalışıyorsa
            return 1;
        }
    }
    return 0; // Hiçbir tracked PID çalışmıyor
}

// Güncellenmiş paket işleme fonksiyonu
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14); // IPv4 başlık
    int ttl = ip_header->ip_ttl;

    // Tüm TCP ve UDP paketleri düşük gecikmeli olarak işaretlenir
    if (ip_header->ip_p == IPPROTO_TCP || ip_header->ip_p == IPPROTO_UDP) {
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sockfd < 0) return;

        // QoS etiketi düşük gecikmeli olarak ayarlanır
        int tos = IPTOS_LOWDELAY;
        setsockopt(sockfd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));

        // Sadece TTL 65 olan paketlerin TTL değeri değiştirilir
        if (ttl == TTL_TARGET) {
            ip_header->ip_ttl = NEW_TTL;
        }

        struct sockaddr_in dest_addr;
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_addr = ip_header->ip_dst;

        sendto(sockfd, packet + 14, header->len - 14, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        close(sockfd);
    }
}

// Uygulama PID’sini ve child process'lerini düzenli olarak kontrol eder, kapanırsa programı sonlandırır
void *pid_monitor(void *arg) {
    while (keep_running) {
        // Ana uygulama kapanırsa veya hiçbir tracked PID çalışmıyorsa program sonlanır
        if (get_pid_from_path((const char *)arg) == -1 && !are_tracked_pids_running()) {
            printf("Ana uygulama veya child process'ler kapandı, program sonlanıyor...\n");
            keep_running = 0;
            pcap_breakloop(handle_global);
            break;
        }

        // Yeni child process'leri izlemeye ekle
        pid_count = 0;  // PID listesi sıfırlanır ve ana uygulama ile child process'ler tekrar takip edilir
        track_child_pids(main_pid);
        
        sleep(1); // Her saniye kontrol
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

    if (argc < 2) {
        printf("Kullanım: %s <uygulama_yolu>\n", argv[0]);
        return 1;
    }

    // Ana uygulamanın PID’sini al
    main_pid = get_pid_from_path(argv[1]);
    if (main_pid == -1) {
        printf("Ana uygulama bulunamadı veya izlenemiyor: %s\n", argv[1]);
        return 1;
    }
    printf("Ana uygulama: %s, PID: %d\n", argv[1], main_pid);

    // Ana uygulama ve child process'leri izlemeye başla
    track_child_pids(main_pid);

    // Ağ arayüzünü belirle
    char *dev = get_default_interface();
    printf("Kullanılan ağ arayüzü: %s\n", dev);

    char errbuf[PCAP_ERRBUF_SIZE];
    handle_global = pcap_open_live(dev, BUFFER_SIZE, 1, 1000, errbuf);
    if (handle_global == NULL) {
        fprintf(stderr, "Cihaz açılamadı: %s\n", errbuf);
        return 2;
    }
    printf("Dinleme başlatıldı... TTL %d veya Hop Limit %d olan paketler işlenecek.\n", TTL_TARGET, HOP_LIMIT_TARGET);

    // PID monitor thread'i oluştur
    pthread_t monitor_thread;
    if (pthread_create(&monitor_thread, NULL, pid_monitor, (void *)argv[1]) != 0) {
        perror("PID monitor thread oluşturulamadı");
        pcap_close(handle_global);
        return 3;
    }

    // Paket dinlemeye başla
    if (pcap_loop(handle_global, 0, packet_handler, NULL) < 0 && keep_running) {
        fprintf(stderr, "pcap_loop hatası: %s\n", pcap_geterr(handle_global));
    }

    // Temizleme ve çıkış
    pthread_join(monitor_thread, NULL);
    pcap_close(handle_global);
    printf("Program düzgün bir şekilde sonlandırıldı.\n");
    return 0;
}
