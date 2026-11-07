//! Actual laboratory policy installation order, shared by the Win32 installer
//! and tests. This is not an ownership oracle or a no-DIRECT acceptance gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family { V4, V6 }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind { Redirect, BlockNonLoopback, BlockWrongPort }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule { pub family: Family, pub kind: Kind }
pub const RULES:[Rule;6]=[
    Rule{family:Family::V4,kind:Kind::BlockNonLoopback},
    Rule{family:Family::V4,kind:Kind::BlockWrongPort},
    Rule{family:Family::V6,kind:Kind::BlockNonLoopback},
    Rule{family:Family::V6,kind:Kind::BlockWrongPort},
    Rule{family:Family::V4,kind:Kind::Redirect},
    Rule{family:Family::V6,kind:Kind::Redirect},
];
#[derive(Debug,PartialEq,Eq)]
pub struct PolicyError(pub &'static str,pub u32);
pub struct Plan { pub appid:Vec<u8>,pub ports:[u16;2] }
impl Plan {
    pub fn new(appid:&[u8],ports:[u16;2])->Result<Self,PolicyError>{
        // This is the exact blob returned by FwpmGetAppIdFromFileName0. Keep its
        // UTF-16 terminator for BFE comparison; kernel ARM strips only that tail.
        if appid.len()<4||appid.len()>514||appid.len()%2!=0||!appid.ends_with(&[0,0])
            ||appid[..appid.len()-2].chunks_exact(2).any(|v|v==[0,0])||ports.contains(&0){
            return Err(PolicyError("policy_input",0));
        }
        Ok(Self{appid:appid.to_vec(),ports})
    }
    pub fn port(&self,f:Family)->u16{self.ports[if f==Family::V4{0}else{1}]}
}
pub trait Operations {
    fn begin(&mut self)->Result<(),PolicyError>;
    fn sublayer(&mut self)->Result<(),PolicyError>;
    fn callout(&mut self,f:Family)->Result<(),PolicyError>;
    fn filter(&mut self,rule:Rule,plan:&Plan)->Result<(),PolicyError>;
    fn commit(&mut self)->Result<(),PolicyError>;
    fn verify(&mut self,rule:Rule,plan:&Plan)->Result<(),PolicyError>;
    fn abort(&mut self)->Result<(),PolicyError>;
}
/// Native implementation owns a fresh DYNAMIC session. Failure after commit
/// closes that session, removing only its own objects, never global policies.
pub fn install(api:&mut impl Operations,plan:&Plan)->Result<(),PolicyError>{
    api.begin()?;
    let stage=(||{
        api.sublayer()?;
        api.callout(Family::V4)?;api.callout(Family::V6)?;
        for rule in RULES{api.filter(rule,plan)?;}
        api.commit()
    })();
    if let Err(error)=stage{
        return match api.abort(){Ok(())=>Err(error),Err(abort)=>Err(abort)};
    }
    for rule in RULES{api.verify(rule,plan)?;}
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Default)]struct Fake{calls:Vec<String>,fail:Option<usize>,aborts:usize}
    impl Fake{fn step(&mut self,s:String)->Result<(),PolicyError>{self.calls.push(s);if self.fail==Some(self.calls.len()){Err(PolicyError("injected",1))}else{Ok(())}}}
    impl Operations for Fake{
        fn begin(&mut self)->Result<(),PolicyError>{self.step("begin".into())}
        fn sublayer(&mut self)->Result<(),PolicyError>{self.step("sublayer".into())}
        fn callout(&mut self,f:Family)->Result<(),PolicyError>{self.step(format!("callout:{f:?}"))}
        fn filter(&mut self,r:Rule,p:&Plan)->Result<(),PolicyError>{assert_eq!(p.appid,vec![97,0,0,0]);self.step(format!("filter:{r:?}"))}
        fn commit(&mut self)->Result<(),PolicyError>{self.step("commit".into())}
        fn verify(&mut self,r:Rule,_:&Plan)->Result<(),PolicyError>{self.step(format!("verify:{r:?}"))}
        fn abort(&mut self)->Result<(),PolicyError>{self.aborts+=1;Ok(())}
    }
    fn plan()->Plan{Plan::new(&[97,0,0,0],[1091,1092]).unwrap()}
    #[test]fn transaction_and_readback_order(){let mut a=Fake::default();install(&mut a,&plan()).unwrap();assert_eq!(a.calls.len(),17);assert_eq!(a.calls[10],"commit");assert!(a.calls[11].starts_with("verify"));assert_eq!(a.aborts,0);}
    #[test]fn each_precommit_error_aborts_once(){for n in 2..=11{let mut a=Fake{fail:Some(n),..Fake::default()};assert!(install(&mut a,&plan()).is_err());assert_eq!(a.aborts,1);assert_eq!(a.calls.len(),n);}}
    #[test]fn begin_error_does_not_abort_unknown_transaction(){let mut a=Fake{fail:Some(1),..Fake::default()};assert!(install(&mut a,&plan()).is_err());assert_eq!(a.aborts,0);}
    #[test]fn readback_failure_is_not_install_success(){for n in 12..=17{let mut a=Fake{fail:Some(n),..Fake::default()};assert!(install(&mut a,&plan()).is_err());assert_eq!(a.aborts,0);}}
    #[test]fn policies_never_have_global_or_permit_rule(){assert_eq!(RULES.iter().filter(|r|r.kind==Kind::Redirect).count(),2);for f in [Family::V4,Family::V6]{assert_eq!(RULES.iter().filter(|r|r.family==f).count(),3);}}
    #[test]fn wildcard_empty_or_interior_nul_identity_rejected(){for b in [&[][..],&[0,0],&[97,0],&[97,0,0,0,98,0,0,0],&[97,0,0]]{assert!(Plan::new(b,[1,2]).is_err());}}
    #[test]fn zero_broker_ports_rejected(){assert!(Plan::new(&[97,0,0,0],[0,2]).is_err());assert!(Plan::new(&[97,0,0,0],[1,0]).is_err());}
    #[test]fn family_port_is_not_swapped(){let p=plan();assert_eq!(p.port(Family::V4),1091);assert_eq!(p.port(Family::V6),1092);}
}
