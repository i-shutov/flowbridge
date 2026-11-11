#!/usr/bin/env python3
"""Static Rust source/ctypes ABI checks; not Windows/SDK/runtime verification."""
import ctypes as C
from pathlib import Path
source = Path(__file__).with_name('r103_readonly_arbitration_inventory.rs').read_text()
class Guid(C.Structure):
    _fields_ = [('d1',C.c_uint32),('d2',C.c_uint16),('d3',C.c_uint16),('d4',C.c_uint8*8)]
class Display(C.Structure):
    _fields_ = [('name',C.c_void_p),('description',C.c_void_p)]
class Blob(C.Structure):
    _fields_ = [('size',C.c_uint32),('data',C.c_void_p)]
class Value(C.Structure):
    _fields_ = [('kind',C.c_uint32),('padding',C.c_uint32),('bits',C.c_uint64)]
class Action(C.Structure):
    _fields_ = [('kind',C.c_uint32),('key',Guid)]
class Cond(C.Structure):
    _fields_ = [('key',Guid),('match',C.c_uint32),('value',Value)]
class Filter(C.Structure):
    _fields_ = [('key',Guid),('display',Display),('flags',C.c_uint32),
                ('provider',C.c_void_p),('provider_data',Blob),('layer',Guid),
                ('sublayer',Guid),('weight',Value),('num_conditions',C.c_uint32),
                ('conditions',C.c_void_p),('action',Action),('context',C.c_uint64*2),
                ('reserved',C.c_void_p),('filter_id',C.c_uint64),('effective_weight',Value)]
expected = [('GUID', C.sizeof(Guid), 16), ('BLOB', C.sizeof(Blob), 16),
            ('VALUE', C.sizeof(Value), 16), ('ACTION', C.sizeof(Action), 20),
            ('CONDITION', C.sizeof(Cond), 40),('FILTER', C.sizeof(Filter), 200),
            ('ACTION_OFFSET',Filter.action.offset,128),
            ('FILTERID_OFFSET',Filter.filter_id.offset,176),
            ('EFFECTIVE_OFFSET',Filter.effective_weight.offset,184)]
assert all(actual==want for _,actual,want in expected), expected
for required in ('FWPM_TXN_READ_ONLY:u32=1',
                 'FwpmTransactionBegin0(engine,FWPM_TXN_READ_ONLY)',
                 'FwpmFilterCreateEnumHandle0(engine.0,ptr::null(),&mut eh)',
                 'FwpmFilterEnum0(engine.0,enumerator.enumerator,PAGE,',
                 'enumerator.destroy()?', 'txn.commit()?',
                 'acl_hidden_filters_possible', 'kernel_proof', 'no_direct_proof',
                 'UNKNOWN_NO_VISIBLE_CANDIDATE'):
    assert required in source, required
for forbidden in ('FwpmFilterAdd0', 'FwpmCalloutAdd0', 'FwpmFilterDeleteByKey0',
                  'FwpmSubLayerAdd0', 'FwpmEngineSetOption0', 'std::net::',
                  'TcpStream', 'UdpSocket', 'Command::new'):
    assert forbidden not in source, forbidden
print(f'R103 STATIC ABI/source guards PASS: {len(expected)} ABI models; no write, driver, socket or process invocation symbols')
