//! Scoped laboratory BFE activation using Microsoft-generated Win32 bindings.
//! Own DYNAMIC session: no foreign-object deletion, persistent-policy or G2 claim.
//! Signed-driver/VNC/rescue/rollback admission is an EXTERNAL prerequisite.
use std::{ffi::c_void,ptr,slice};
use windows_sys::{core::GUID,Win32::{Foundation::HANDLE,NetworkManagement::WindowsFilteringPlatform::*}};
use crate::policy_plan::{self,Family,Kind,Operations,Plan,PolicyError,Rule,RULES};
const SUB:GUID=GUID::from_u128(0x1649f024_25b3_4e01_9ca1_5ca803010019);
fn callout_key(f:Family)->GUID{GUID::from_u128(if f==Family::V4{0x1649f014_25b3_4e01_9ca1_5ca803010019}else{0x1649f016_25b3_4e01_9ca1_5ca803010019})}
fn filter_key(r:Rule)->GUID{let n=RULES.iter().position(|x|*x==r).expect("fixed rule");GUID::from_u128(0x1649f030_25b3_4e01_9ca1_5ca803010019+((n as u128)<<96))}
fn redirect_layer(f:Family)->GUID{if f==Family::V4{FWPM_LAYER_ALE_CONNECT_REDIRECT_V4}else{FWPM_LAYER_ALE_CONNECT_REDIRECT_V6}}
fn layer(r:Rule)->GUID{if r.kind==Kind::Redirect{redirect_layer(r.family)}else if r.family==Family::V4{FWPM_LAYER_ALE_AUTH_CONNECT_V4}else{FWPM_LAYER_ALE_AUTH_CONNECT_V6}}
fn name()->Vec<u16>{"FlowBridge G2 scoped native lab R24\0".encode_utf16().collect()}
fn check(code:u32,stage:&'static str)->Result<(),PolicyError>{if code==0{Ok(())}else{Err(PolicyError(stage,code))}}
fn require(ok:bool,stage:&'static str)->Result<(),PolicyError>{if ok{Ok(())}else{Err(PolicyError(stage,0))}}
struct Owned<T>(*mut T);
impl<T> Drop for Owned<T>{fn drop(&mut self){if !self.0.is_null(){unsafe{let mut p=self.0.cast::<c_void>();FwpmFreeMemory0(&mut p);}}}}
struct Engine{handle:HANDLE}
impl Engine{
 fn open()->Result<Self,PolicyError>{
  let mut session=FWPM_SESSION0::default();session.flags=FWPM_SESSION_FLAG_DYNAMIC;session.txnWaitTimeoutInMSec=5000;
  let mut n=name();session.displayData.name=n.as_mut_ptr();let mut e=Self{handle:ptr::null_mut()};
  unsafe{check(FwpmEngineOpen0(ptr::null(),10,ptr::null(),&session,&mut e.handle),"open_dynamic_session")?;}
  require(!e.handle.is_null(),"null_engine")?;Ok(e)
 }
 fn close(mut self)->Result<(),PolicyError>{let h=std::mem::replace(&mut self.handle,ptr::null_mut());unsafe{check(FwpmEngineClose0(h),"close_dynamic_session")}}
}
impl Drop for Engine{fn drop(&mut self){if !self.handle.is_null(){unsafe{FwpmEngineClose0(self.handle);}}}}
pub struct Installed{engine:Engine}
impl Installed{
 /// The caller must independently admit the signed-driver test host and have
 /// verified current VNC/SYSTEM rescue/rollback. This function does not do so.
 pub unsafe fn activate_admitted(plan:&Plan)->Result<Self,PolicyError>{let mut engine=Engine::open()?;policy_plan::install(&mut engine,plan)?;Ok(Self{engine})}
 /// The native harness must terminate selected test clients before teardown.
 pub fn close(self)->Result<(),PolicyError>{self.engine.close()}
}
fn conditions(r:Rule,p:&Plan,blob:&mut FWP_BYTE_BLOB,v6:&mut FWP_BYTE_ARRAY16)->Vec<FWPM_FILTER_CONDITION0>{
 blob.size=p.appid.len()as u32;blob.data=p.appid.as_ptr().cast_mut();
 let mut app=FWPM_FILTER_CONDITION0::default();app.fieldKey=FWPM_CONDITION_ALE_APP_ID;app.matchType=FWP_MATCH_EQUAL;
 app.conditionValue.r#type=FWP_BYTE_BLOB_TYPE;app.conditionValue.Anonymous.byteBlob=blob;
 let mut tcp=FWPM_FILTER_CONDITION0::default();tcp.fieldKey=FWPM_CONDITION_IP_PROTOCOL;tcp.matchType=FWP_MATCH_EQUAL;
 tcp.conditionValue.r#type=FWP_UINT8;tcp.conditionValue.Anonymous.uint8=6;let mut list=vec![app,tcp];
 if r.kind!=Kind::Redirect{
  let mut c=FWPM_FILTER_CONDITION0::default();c.matchType=FWP_MATCH_NOT_EQUAL;
  if r.kind==Kind::BlockWrongPort{c.fieldKey=FWPM_CONDITION_IP_REMOTE_PORT;c.conditionValue.r#type=FWP_UINT16;c.conditionValue.Anonymous.uint16=p.port(r.family);}
  else{c.fieldKey=FWPM_CONDITION_IP_REMOTE_ADDRESS;
   if r.family==Family::V4{c.conditionValue.r#type=FWP_UINT32;c.conditionValue.Anonymous.uint32=0x7f000001;}
   else{v6.byteArray16=[0;16];v6.byteArray16[15]=1;c.conditionValue.r#type=FWP_BYTE_ARRAY16_TYPE;c.conditionValue.Anonymous.byteArray16=v6;}
  }list.push(c);
 }list
}
fn filter(r:Rule,c:&mut[FWPM_FILTER_CONDITION0],n:&mut[u16])->FWPM_FILTER0{
 let mut f=FWPM_FILTER0::default();f.filterKey=filter_key(r);f.subLayerKey=SUB;f.layerKey=layer(r);f.displayData.name=n.as_mut_ptr();f.weight.r#type=FWP_EMPTY;
 f.numFilterConditions=c.len()as u32;f.filterCondition=c.as_mut_ptr();
 // No PERMIT_IF_CALLOUT_UNREGISTERED, DISABLED, PERSISTENT, or global PERMIT.
 f.flags=0;f.action.r#type=if r.kind==Kind::Redirect{FWP_ACTION_CALLOUT_UNKNOWN}else{FWP_ACTION_BLOCK};
 if r.kind==Kind::Redirect{f.action.Anonymous.calloutKey=callout_key(r.family);}f
}
impl Operations for Engine{
 fn begin(&mut self)->Result<(),PolicyError>{unsafe{check(FwpmTransactionBegin0(self.handle,0),"begin")}}
 fn abort(&mut self)->Result<(),PolicyError>{unsafe{check(FwpmTransactionAbort0(self.handle),"abort")}}
 fn commit(&mut self)->Result<(),PolicyError>{unsafe{check(FwpmTransactionCommit0(self.handle),"commit")}}
 fn sublayer(&mut self)->Result<(),PolicyError>{let mut s=FWPM_SUBLAYER0::default();let mut n=name();s.subLayerKey=SUB;s.displayData.name=n.as_mut_ptr();s.weight=0x7000;
  unsafe{check(FwpmSubLayerAdd0(self.handle,&s,ptr::null_mut()),"add_owned_sublayer")}}
 fn callout(&mut self,f:Family)->Result<(),PolicyError>{
  let mut c=FWPM_CALLOUT0::default();let mut n=name();c.calloutKey=callout_key(f);c.applicableLayer=redirect_layer(f);c.displayData.name=n.as_mut_ptr();
  unsafe{check(FwpmCalloutAdd0(self.handle,&c,ptr::null_mut(),ptr::null_mut()),"add_owned_callout")?;
   let mut p=ptr::null_mut();let status=FwpmCalloutGetByKey0(self.handle,&c.calloutKey,&mut p);let owned=Owned(p);
   check(status,"query_runtime_registration")?;require(!owned.0.is_null(),"null_callout")?;
   // Query-only registration status is a prerequisite snapshot, never proof
   // of the original process of any connection.
   require((*owned.0).flags&FWPM_CALLOUT_FLAG_REGISTERED!=0,"kernel_callout_not_registered")
  }
 }
 fn filter(&mut self,r:Rule,p:&Plan)->Result<(),PolicyError>{
  let mut blob=FWP_BYTE_BLOB::default();let mut addr=FWP_BYTE_ARRAY16::default();let mut n=name();
  let mut c=conditions(r,p,&mut blob,&mut addr);let f=filter(r,&mut c,&mut n);
  unsafe{check(FwpmFilterAdd0(self.handle,&f,ptr::null_mut(),ptr::null_mut()),"add_scoped_filter")}
 }
 fn verify(&mut self,r:Rule,plan:&Plan)->Result<(),PolicyError>{unsafe{
  let mut raw=ptr::null_mut();let status=FwpmFilterGetByKey0(self.handle,&filter_key(r),&mut raw);let owned=Owned(raw);
  check(status,"readback_filter")?;require(!owned.0.is_null(),"null_filter")?;let f=&*owned.0;
  require(f.filterKey==filter_key(r)&&f.subLayerKey==SUB&&f.layerKey==layer(r)&&f.flags==0,"filter_scope_changed")?;
  require(f.action.r#type==if r.kind==Kind::Redirect{FWP_ACTION_CALLOUT_UNKNOWN}else{FWP_ACTION_BLOCK},"filter_action_changed")?;
  if r.kind==Kind::Redirect{require(f.action.Anonymous.calloutKey==callout_key(r.family),"wrong_callout")?;}
  let count=if r.kind==Kind::Redirect{2}else{3};require(f.numFilterConditions==count&&!f.filterCondition.is_null(),"condition_count")?;
  let cs=slice::from_raw_parts(f.filterCondition,count as usize);
  let app=cs.iter().find(|c|c.fieldKey==FWPM_CONDITION_ALE_APP_ID).ok_or(PolicyError("appid_condition_missing",0))?;
  require(app.matchType==FWP_MATCH_EQUAL&&app.conditionValue.r#type==FWP_BYTE_BLOB_TYPE,"appid_condition_type")?;
  let b=app.conditionValue.Anonymous.byteBlob;require(!b.is_null(),"null_appid")?;
  require((*b).size as usize==plan.appid.len()&&!(*b).data.is_null(),"appid_size")?;
  require(slice::from_raw_parts((*b).data,(*b).size as usize)==plan.appid,"appid_changed")?;
  let tcp=cs.iter().find(|c|c.fieldKey==FWPM_CONDITION_IP_PROTOCOL).ok_or(PolicyError("tcp_missing",0))?;
  require(tcp.matchType==FWP_MATCH_EQUAL&&tcp.conditionValue.r#type==FWP_UINT8&&tcp.conditionValue.Anonymous.uint8==6,"tcp_changed")?;
  if r.kind!=Kind::Redirect{
   let key=if r.kind==Kind::BlockWrongPort{FWPM_CONDITION_IP_REMOTE_PORT}else{FWPM_CONDITION_IP_REMOTE_ADDRESS};
   let c=cs.iter().find(|c|c.fieldKey==key).ok_or(PolicyError("auth_condition_missing",0))?;require(c.matchType==FWP_MATCH_NOT_EQUAL,"auth_match_changed")?;
   let good=if r.kind==Kind::BlockWrongPort{c.conditionValue.r#type==FWP_UINT16&&c.conditionValue.Anonymous.uint16==plan.port(r.family)}
    else if r.family==Family::V4{c.conditionValue.r#type==FWP_UINT32&&c.conditionValue.Anonymous.uint32==0x7f000001}
    else{let a=c.conditionValue.Anonymous.byteArray16;c.conditionValue.r#type==FWP_BYTE_ARRAY16_TYPE&&!a.is_null()&&(*a).byteArray16==[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]};
   require(good,"auth_destination_changed")?;
  }Ok(())
 }}
}
/// Constructs the same FWP objects as the installer without opening a BFE session.
pub fn verify_plan_only(p:&Plan)->Result<(),PolicyError>{
 for r in RULES{let mut blob=FWP_BYTE_BLOB::default();let mut a=FWP_BYTE_ARRAY16::default();let mut n=name();let mut c=conditions(r,p,&mut blob,&mut a);let f=filter(r,&mut c,&mut n);
  require(f.flags==0&&f.numFilterConditions>=2&&f.layerKey==layer(r),"plan_invalid")?;
  require(f.action.r#type!=FWP_ACTION_PERMIT,"unintended_permit")?;
  require(c[0].fieldKey==FWPM_CONDITION_ALE_APP_ID&&c[0].matchType==FWP_MATCH_EQUAL,"unscoped_filter")?;
  if r.kind==Kind::BlockWrongPort{unsafe{require(c[2].conditionValue.Anonymous.uint16==p.port(r.family),"port_wrong")?;}}
 }Ok(())
}
#[cfg(test)]mod tests{
 use super::*;
 #[test]fn actual_win32_plan_is_scoped_and_nonpermissive(){let p=Plan::new(&[97,0,0,0],[1091,1092]).unwrap();verify_plan_only(&p).unwrap();}
 #[test]fn all_filter_keys_unique(){for(i,a)in RULES.iter().enumerate(){for b in &RULES[i+1..]{assert!(filter_key(*a)!=filter_key(*b));}}}
 #[test]fn static_kernel_callout_keys_match_r19(){assert_eq!(callout_key(Family::V4).data1,0x1649f014);assert_eq!(callout_key(Family::V6).data1,0x1649f016);}
}
