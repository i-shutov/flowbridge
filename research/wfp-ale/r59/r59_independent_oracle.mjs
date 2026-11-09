#!/usr/bin/env node
// Independent R59 closed-world WFP layer/API model. No imports from Python.
// These arrays are a hand-transcribed official documented-use table, not a
// guarantee about the runtime STATUS_SUCCESS or about actual Windows packets.
import { createHash } from 'node:crypto';
const layers = ['RESOURCE_ASSIGNMENT','AUTH_LISTEN','AUTH_CONNECT','ENDPOINT_CLOSURE',
                'CONNECT_REDIRECT','BIND_REDIRECT','AUTH_RECV_ACCEPT','FLOW_ESTABLISHED','STREAM'];
const membership = {
  OPERATION: new Set(['RESOURCE_ASSIGNMENT','AUTH_LISTEN','AUTH_CONNECT']),
  CLASSIFY: new Set(['ENDPOINT_CLOSURE','CONNECT_REDIRECT','BIND_REDIRECT'])
};
const counts = new Map();
const hash = createHash('sha256');
let n = 0;
for (const family of [4,6]) {
for (const layer of layers) {
for (const api of ['OPERATION','CLASSIFY']) {
for (const reauth of [false,true]) {
for (const status of ['SUCCESS','CANNOT_PEND']) {
for (const completion of ['NULL','FINAL']) {
for (const handle of [false,true]) {
for (const invoked of [false,true]) {
for (const originalOwner of [false,true]) {
for (const ssh of [false,true]) {
for (const wfp of [false,true]) {
for (const protocol of ['TCP','UDP']) {
  let result;
  if (invoked === false) result = 'UNOBSERVED';
  else if (protocol === 'UDP') result = 'OUTSIDE_TCP_PROOF';
  else if (!membership[api].has(layer)) result = 'UNDOCUMENTED_FOR_API';
  else if (api === 'OPERATION' && layer === 'AUTH_CONNECT' && reauth) result = 'OPERATION_CANNOT_PEND_REAUTH';
  else if (!handle) result = 'NO_VALID_HANDLE';
  else if (status !== 'SUCCESS') result = 'PEND_FAILED';
  else if (!originalOwner) result = 'NO_KERNEL_ORIGIN_PROOF';
  else if (!ssh || !wfp) result = 'REVOKED';
  else if (api === 'OPERATION') result = layer === 'AUTH_CONNECT' ? 'AUTH_REAUTH_REQUIRED' : 'OPERATION_RESUMES';
  else if (completion === 'NULL') result = 'CLASSIFY_REAUTH_REQUIRED';
  else result = 'CONDITIONAL_FINAL_CALLOUT_ONLY';
  n++;
  counts.set(result, (counts.get(result) || 0)+1);
  hash.update(result+'\n');
}}}}}}}}}}}}
const ordered = Object.fromEntries([...counts.entries()].sort((a,b)=>a[0].localeCompare(b[0],'en')));
const out = {
  states: n,
  counts: ordered,
  decision_stream_sha256: hash.digest('hex'),
  conditional_physical_permits: 0,
  native_windows_tests: 0
};
console.log(JSON.stringify(out,null,2));
