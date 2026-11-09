// Independent offline oracle, no platform or network calls.
import{createHash}from'node:crypto';
const modes=['normal','circular_overwrite','disabled','reboot','enum_snapshot_before_event'];
const c={total:0,naive:0,actual:0,false_join:0,false_no_direct:0,missing_history:0,claimed_identity:0,claimed_no_direct:0,v4:0,v6:0,tcp:0,udp:0},h=createHash('sha256');
for(let f of[4,6])for(let p of[6,17])for(let a of[0,1])for(let t of[0,1])for(let w of[0,1])for(let fl of[0,1])for(let e of[0,1])for(let s of[0,1])for(let d of[0,1])for(let m of modes)for(let o of[0,1])for(let direct of[0,1]){
const n=+(p===6&&!!a&&!!t&&!!w&&!!fl&&!!d),ok=+(n===1&&!!e&&!!s&&!!o),falseJoin=+(n===1&&!ok),falseDirect=+(n===1&&!!direct),missing=+(m!=='normal');
const fields=[f,p,a,t,w,fl,e,s,d,m,o,direct,n,ok,falseJoin,falseDirect,missing,0,0];h.update(fields.join('|')+'\n');
c.total++;c['v'+f]++;c[p===6?'tcp':'udp']++;c.naive+=n;c.actual+=ok;c.false_join+=falseJoin;c.false_no_direct+=falseDirect;c.missing_history+=missing;
}
c.sha256=h.digest('hex');console.log(JSON.stringify(Object.fromEntries(Object.entries(c).sort(([a],[b])=>a.localeCompare(b)))));
