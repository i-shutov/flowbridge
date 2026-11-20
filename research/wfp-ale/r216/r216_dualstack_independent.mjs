// R216 independent Node.js oracle (NOT imported from the Python model).
// No network, WFP, sockets, driver or external dependencies.
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';

function parseV4(text) { return [...text.split('.').map(Number), ...Array(12).fill(0)]; }
function parseV6(bytes) { return bytes; }
function mapped(ip4) { return [...Array(10).fill(0), 255, 255, ...ip4.split('.').map(Number)]; }
function accepted(family, b, port=443) {
  if (port===0 || b.length!==16) return false;
  if (family===4) return b.slice(4).every(v=>v===0) && b.slice(0,4).some(v=>v!==0) && b[0]<224;
  if (family!==6) return false;
  const empty=b.every(v=>v===0), multicast=b[0]===255;
  const linkLocal=b[0]===254 && (b[1]&192)===128;
  const isMapped=b.slice(0,10).every(v=>v===0) && b[10]===255 && b[11]===255;
  return !(empty || multicast || linkLocal || isMapped);
}
const allZero=Array(16).fill(0);
const loopback=[...Array(15).fill(0),1];
const global=[0x20,0x01,0x0d,0xb8,...Array(11).fill(0),7];
const linkLocal=[0xfe,0x80,...Array(13).fill(0),1];
const multicast=[0xff,0x02,...Array(13).fill(0),1];
const scenarios=[
 ['v4_unicast',4,parseV4('198.51.100.7'),true],
 ['v4_loopback',4,parseV4('127.0.0.1'),true],
 ['v4_unspecified',4,parseV4('0.0.0.0'),false],
 ['v4_multicast',4,parseV4('224.0.0.1'),false],
 ['v6_global',6,parseV6(global),true],
 ['v6_loopback',6,parseV6(loopback),true],
 ['v6_unspecified',6,parseV6(allZero),false],
 ['v6_linklocal',6,parseV6(linkLocal),false],
 ['v6_multicast',6,parseV6(multicast),false],
 ['v6_mapped_public',6,mapped('198.51.100.7'),false],
 ['v6_mapped_loopback',6,mapped('127.0.0.1'),false],
 ['v6_mapped_private',6,mapped('10.0.0.2'),false]
];
assert.equal(scenarios.length,12);
let transcript='';
for(const [name,family,ip,expect] of scenarios){
 const result=accepted(family,ip);
 assert.equal(result,expect,name);
 transcript+=`${name}\t${family}\t${Buffer.from(ip).toString('hex')}\t${Number(result)}\n`;
}
const v4=accepted(4,parseV4('198.51.100.7'));
const v6mapped=accepted(6,mapped('198.51.100.7'));
assert.equal(v4,true);assert.equal(v6mapped,false);
const m=mapped('198.51.100.7');
const mutant=!m.every(v=>v===0) && m[0]!==255 && !(m[0]===254 && (m[1]&192)===128);
assert.equal(mutant,true); assert.notEqual(mutant,v6mapped);
console.log('R216 rows=12 sha256='+createHash('sha256').update(transcript,'ascii').digest('hex'));
