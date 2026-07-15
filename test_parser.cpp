// test_parser.cpp
//
// Minimal, dependency-free test harness for the packet parser.
// No network access needed -- every "packet" here is a hand-built
// byte array, so we know exactly what should come out the other end.
//
// Run it, read the PASS/FAIL lines, and check the final count.
// Exit code 0 = everything passed, non-zero = something failed
// (useful later if you ever wire this into GitHub Actions).
 
#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/if_ether.h>
#include "packet.h"
#include "parser.h"
 
// ---- tiny helpers to keep each test short and readable ----
 
static int tests_run = 0;
static int tests_passed = 0;
 
void check(bool condition, const std::string& description){
    tests_run++;
    if(condition){
        std::cout << "[PASS] " << description << "\n";
        tests_passed++;
    } else {
        std::cout << "[FAIL] " << description << "\n";
    }
}
 
// ---- Test 1: buffer too small for even an Ethernet header ----
void test_truncated_ethernet(){
    unsigned char tiny_buffer[5] = {0x01, 0x02, 0x03, 0x04, 0x05};
    packet p(tiny_buffer, 5); // a real eth header needs 14 bytes
    parser chop(p);
 
    Eth_Header eth = chop.extract_ethernet_header();
    check(eth.protocol == -1, "truncated buffer (5 bytes) is flagged invalid, not parsed as real Ethernet");
}
 
// ---- Test 2: big enough for Ethernet, too small for a full IP header ----
void test_truncated_ip(){
    // 14 bytes of Ethernet header + only 5 bytes after it (not enough for a 20-byte IP header)
    unsigned char buf[19] = {0};
    ethhdr* eth = (ethhdr*)buf;
    eth->h_proto = htons(ETH_P_IP); // claim "this is IPv4" so we actually reach the IP parsing path
 
    packet p(buf, sizeof(buf));
    parser chop(p);
 
    IP_Header ip = chop.extract_ip_header();
    // get_ip_header() should have returned nullptr internally, so extraction
    // fields should still be at their defaults (protocol not set to anything real)
    check(ip.source_IP.empty() && ip.dest_IP.empty(),
          "truncated IP header (19 bytes total) yields an empty/default IP_Header instead of reading garbage");
}
 
// ---- Test 3: a fully well-formed IPv4 + TCP packet, built by hand ----
// This is the "happy path" test -- confirms real parsing still works correctly,
// not just that failures are handled.
void test_valid_tcp_packet(){
    unsigned char buf[14 + 20 + 20]; // eth + ip (no options) + tcp (no options)
    std::memset(buf, 0, sizeof(buf));
 
    // --- Ethernet header ---
    ethhdr* eth = (ethhdr*)buf;
    eth->h_proto = htons(ETH_P_IP);
    // source/dest MACs left as zero -- irrelevant for this test
 
    // --- IP header ---
    iphdr* ip = (iphdr*)(buf + sizeof(ethhdr));
    ip->ihl = 5;           // 5 * 4 = 20 bytes, no IP options
    ip->version = 4;
    ip->tot_len = htons(sizeof(iphdr) + sizeof(tcphdr));
    ip->protocol = IPPROTO_TCP; // 6
    ip->saddr = inet_addr("192.168.1.10");
    ip->daddr = inet_addr("192.168.1.20");
 
    // --- TCP header ---
    tcphdr* tcp = (tcphdr*)(buf + sizeof(ethhdr) + sizeof(iphdr));
    tcp->source = htons(443);
    tcp->dest = htons(51000);
    tcp->seq = htonl(1000);
    tcp->th_off = 5; // 5 * 4 = 20 bytes, no TCP options
 
    packet p(buf, sizeof(buf));
    parser chop(p);
 
    Parsed_Packet result = chop.parse_all();
 
    check(result.eth.protocol == ETH_P_IP, "valid packet: Ethernet protocol correctly identified as IPv4");
    check(result.has_ip, "valid packet: has_ip flag set");
    check(result.Ip.source_IP == "192.168.1.10", "valid packet: source IP parsed correctly");
    check(result.Ip.dest_IP == "192.168.1.20", "valid packet: dest IP parsed correctly");
    check(result.has_tcp, "valid packet: has_tcp flag set");
    check(result.TCP.source_port == 443, "valid packet: TCP source port parsed correctly");
    check(result.TCP.destination_port == 51000, "valid packet: TCP dest port parsed correctly");
}
 
// ---- Test 4: IP header claims a bigger header (ihl) than the buffer actually has ----
// This is the "malicious/malformed ihl" case -- ip->ihl is attacker-controlled data,
// so get_transport_offset() must not trust it blindly.
void test_malformed_ihl(){
    unsigned char buf[14 + 20]; // just eth + minimal IP header, nothing after
    std::memset(buf, 0, sizeof(buf));
 
    ethhdr* eth = (ethhdr*)buf;
    eth->h_proto = htons(ETH_P_IP);
 
    iphdr* ip = (iphdr*)(buf + sizeof(ethhdr));
    ip->ihl = 15;              // claims a 60-byte IP header (max possible) -- way past our buffer
    ip->version = 4;
    ip->protocol = IPPROTO_TCP;
 
    packet p(buf, sizeof(buf));
    parser chop(p);
 
    chop.extract_TCP_Header();
    // We aren't checking specific field values here -- the real point of this
    // test is that calling extract_TCP_Header() doesn't crash/segfault at all.
    // If we get here without the program dying, the bounds check worked.
    check(true, "malformed ihl (claims 60-byte IP header) does not crash extract_TCP_Header()");
}
 
int main(){
    std::cout << "Running parser test suite...\n\n";
 
    test_truncated_ethernet();
    test_truncated_ip();
    test_valid_tcp_packet();
    test_malformed_ihl();
 
    std::cout << "\n" << tests_passed << "/" << tests_run << " tests passed\n";
 
    return (tests_passed == tests_run) ? 0 : 1;
}