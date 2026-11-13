// Independent Node.js oracle, not a translation of the Python function.
// A 32-slot FIFO stores one record per possible selected ALE observe event.
for (const af of [4, 6]) {
  for (const producer of [false,true]) {
    for (const reader of ['none','each','late']) {
      for (const events of [0,1,31,32,33,34,40]) {
        const buffer = [];
        let fatal = false;
        let born = 0;
        let consumed = 0;
        for (let i=0; i<events; i++) {
          if (producer && !fatal) {
            if (buffer.length >= 32) fatal = true;
            else { buffer.push(i+1); born++; }
          }
          if (producer && reader === 'each' && !fatal && buffer.length) {
            buffer.shift(); consumed++;
          }
        }
        if (producer && reader === 'late' && !fatal && buffer.length) {
          buffer.shift(); consumed++;
        }
        // Python emits sort_keys=True; JSON JS insertion follows lexicographic keys.
        const result = {
          consumed, enqueued: born, events, family: af,
          ledger_lost: fatal, next_ready_kills_book: fatal,
          producer, queued: buffer.length, reader
        };
        process.stdout.write(JSON.stringify(result)+'\n');
      }
    }
  }
}
