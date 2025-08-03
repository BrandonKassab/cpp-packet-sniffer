#include <pcap.h>
#include <iostream>
#include <unordered_map>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <string>

// Lookup table for known IPv6 prefixes (e.g. Google, YouTube)
std::unordered_map<std::string, std::string> known_services = {
    {"2607:f8b0", "Google / YouTube"},
    {"2001:4860", "Google DNS"},
    {"2001:67c:4e8", "RIPE NCC"},
    {"2001:1890", "Cloudflare / DoH"},
    {"2600:1f18", "Amazon AWS"},
};

// Label IPv6 address based on known prefix
std::string label_ipv6(const std::string& ip) {
    for (const auto& [prefix, label] : known_services) {
        if (ip.rfind(prefix, 0) == 0) {  // if ip starts with prefix
            return label;
        }
    }
    return "";
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    const char* device = "en0"; // Change if needed

    // Open device
    pcap_t* handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Could not open device " << device << ": " << errbuf << std::endl;
        return 1;
    }

    std::cout << "Sniffing on device: " << device << " (Press Ctrl+C to stop)\n\n";

    int packet_count = 0;

    while (true) {
        struct pcap_pkthdr header;
        const u_char* packet = pcap_next(handle, &header);
        if (packet == nullptr) {
            continue;
        }

        std::cout << "Packet " << ++packet_count << ": Length " << header.len << " bytes\n";

        const struct ether_header* eth = (struct ether_header*)packet;
        uint16_t ether_type = ntohs(eth->ether_type);

        if (ether_type == ETHERTYPE_IP) {
            const struct ip* ip_hdr = (struct ip*)(packet + sizeof(struct ether_header));
            std::string src_ip = inet_ntoa(ip_hdr->ip_src);
            std::string dst_ip = inet_ntoa(ip_hdr->ip_dst);

            std::cout << "    IPv4 From: " << src_ip << "  -->  To: " << dst_ip << "\n";

            int ip_header_len = ip_hdr->ip_hl * 4;
            const u_char* transport_ptr = packet + sizeof(struct ether_header) + ip_header_len;

            switch (ip_hdr->ip_p) {
                case IPPROTO_TCP: {
                    const struct tcphdr* tcp_hdr = (struct tcphdr*)transport_ptr;
                    std::cout << "    Protocol: TCP\n";
                    std::cout << "    Ports: " << ntohs(tcp_hdr->th_sport)
                              << " -> " << ntohs(tcp_hdr->th_dport) << "\n";
                    break;
                }
                case IPPROTO_UDP: {
                    const struct udphdr* udp_hdr = (struct udphdr*)transport_ptr;
                    std::cout << "    Protocol: UDP\n";
                    std::cout << "    Ports: " << ntohs(udp_hdr->uh_sport)
                              << " -> " << ntohs(udp_hdr->uh_dport) << "\n";
                    break;
                }
                case IPPROTO_ICMP:
                    std::cout << "    Protocol: ICMP (no ports)\n";
                    break;
                default:
                    std::cout << "    Protocol: Other (" << (int)ip_hdr->ip_p << ")\n";
            }

        } else if (ether_type == ETHERTYPE_IPV6) {
            const struct ip6_hdr* ip6_hdr = (struct ip6_hdr*)(packet + sizeof(struct ether_header));

            char src_addr[INET6_ADDRSTRLEN];
            char dst_addr[INET6_ADDRSTRLEN];

            inet_ntop(AF_INET6, &ip6_hdr->ip6_src, src_addr, sizeof(src_addr));
            inet_ntop(AF_INET6, &ip6_hdr->ip6_dst, dst_addr, sizeof(dst_addr));

            std::string src_label = label_ipv6(src_addr);
            std::string dst_label = label_ipv6(dst_addr);

            std::cout << "    IPv6 From: " << src_addr;
            if (!src_label.empty()) std::cout << " [" << src_label << "]";
            std::cout << "  -->  To: " << dst_addr;
            if (!dst_label.empty()) std::cout << " [" << dst_label << "]";
            std::cout << "\n";

            const u_char* transport_ptr = packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr);

            switch (ip6_hdr->ip6_nxt) {
                case IPPROTO_TCP: {
                    const struct tcphdr* tcp_hdr = (struct tcphdr*)transport_ptr;
                    std::cout << "    Protocol: TCP\n";
                    std::cout << "    Ports: " << ntohs(tcp_hdr->th_sport)
                              << " -> " << ntohs(tcp_hdr->th_dport) << "\n";
                    break;
                }
                case IPPROTO_UDP: {
                    const struct udphdr* udp_hdr = (struct udphdr*)transport_ptr;
                    std::cout << "    Protocol: UDP\n";
                    std::cout << "    Ports: " << ntohs(udp_hdr->uh_sport)
                              << " -> " << ntohs(udp_hdr->uh_dport) << "\n";
                    break;
                }
                case IPPROTO_ICMPV6:
                    std::cout << "    Protocol: ICMPv6\n";
                    break;
                default:
                    std::cout << "    Protocol: Other (" << (int)ip6_hdr->ip6_nxt << ")\n";
            }

        } else {
            std::cout << "    Unknown or unsupported EtherType: 0x"
                      << std::hex << ether_type << std::dec << "\n";
        }

        std::cout << std::endl;
    }

    pcap_close(handle);
    return 0;
}
