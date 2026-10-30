#include "flowbridge.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A real foreign caller: validates ownership, linkage and JSON responses.
 * Does not open sockets or change system settings. */
static int check(const char *config, const char *flow) {
    char *validated = fb_validate_json(config);
    if (!validated) return 1;
    int bad = strstr(validated, "\"ok\":true") == NULL;
    fb_string_free(validated);
    if (bad) return 2;
    char *decision = fb_evaluate_json(config, flow);
    if (!decision) return 3;
    bad = strstr(decision, "\"ok\":true") == NULL || strstr(decision, "\"type\":\"direct\"") == NULL;
    fb_string_free(decision);
    return bad ? 4 : 0;
}

int main(void) {
    const char *config = "{\"version\":1,\"listen\":\"127.0.0.1:1081\",\"proxies\":[],\"chains\":[],\"rules\":[],\"default_action\":{\"type\":\"direct\"},\"connect_timeout_ms\":1000,\"handshake_timeout_ms\":1000,\"idle_timeout_ms\":1000,\"max_connections\":10}";
    const char *flow = "{\"application\":null,\"destination\":{\"host\":\"example.com\",\"port\":443},\"resolved_ip\":null}";
    for (int i = 0; i < 1000; ++i) {
        int status = check(config, flow);
        if (status) { fprintf(stderr, "C ABI failure %d\n", status); return status; }
    }
    char *error = fb_validate_json(NULL);
    if (!error || !strstr(error, "\"ok\":false")) { fb_string_free(error); return 5; }
    fb_string_free(error);
    fb_string_free(NULL);
    /* Rust NDISRD capability API is passive on Windows and disabled elsewhere.
     * An ABI response must never imply driver install/signature/traffic PASS. */
    char *ndis = fb_windows_packet_filter_status_json();
    if (!ndis || !strstr(ndis, "\"backend\":\"ndisapi\"") ||
        !strstr(ndis, "\"signature_status\":\"not_checked\"") ||
        !strstr(ndis, "\"driver_installation_attempted\":false") ||
        !strstr(ndis, "\"packet_capture_active\":false") ||
        !strstr(ndis, "\"native_routing_accepted\":false")) {
        fb_string_free(ndis);
        return 6;
    }
    fb_string_free(ndis);
    /* Invalid local ports MUST be rejected, on both Windows and non-Windows.
     * These calls are read-only; a JSON return must not imply interception. */
    char *udp = fb_windows_udp_owner_candidate_json("{\\\"local\\\":\\\"127.0.0.1:0\\\"}");
    if (!udp || !strstr(udp, "\\\"ok\\\":false") ||
        strstr(udp, "\\\"authorizes_capture\\\":true")) {
        fb_string_free(udp);
        return 7;
    }
    fb_string_free(udp);
    char *tcp = fb_windows_tcp_owner_candidate_json("{\\\"local\\\":\\\"127.0.0.1:0\\\",\\\"remote\\\":\\\"127.0.0.1:443\\\"}");
    if (!tcp || !strstr(tcp, "\\\"ok\\\":false") ||
        strstr(tcp, "\\\"authorizes_capture\\\":true")) {
        fb_string_free(tcp);
        return 8;
    }
    fb_string_free(tcp);
    puts("C ABI smoke: 1000 validate/evaluate/free cycles and null handling passed");
    return 0;
}
