// Independently phrased declarative oracle; no kernel/filter/device calls.
const states = ["issued", "attested", "claimed"];
const names = ["selected_redirect", "sibling_direct", "proxy_ssh", "endpoint_aba", "pid_aba"];
for (const family of [4, 6]) {
  for (const phase of states) {
    for (const flow of names) {
      for (const health of ["up", "lost"]) {
        const authorizedInitial = phase === "issued" && flow === "selected_redirect" && health === "up";
        const row = {
          family, phase, flow, health,
          source: "BLOCK_REAUTH", // bit 0x4 rejected before Book::attest
          remove_bit_only: authorizedInitial ? "ATTEST_CANDIDATE" : "DENY",
          naive_app_loopback: flow === "proxy_ssh" ? "BLOCK" : "PERMIT",
        };
        process.stdout.write(JSON.stringify(row) + "\n");
      }
    }
  }
}
