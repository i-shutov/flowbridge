//! R71 pure Rust offline guard. NO FFI/network/driver/filter or unsafe.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Record { Absent, Null, NullHypotheticalClean, NotRedirected, BySelf, ByOther, PreviouslySelf, Unknown }
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Decision { Unobserved, BlockRequested, NoNewRedirect, ConditionalIssue }
pub fn guard(current:bool,tcp:bool,lease:bool,owner:bool,epoch:bool,record:Record)->Decision {
 if !current||!tcp {return Decision::Unobserved;}
 if matches!(record, Record::BySelf|Record::PreviouslySelf) {return Decision::NoNewRedirect;}
 if !(lease&&owner&&epoch){return Decision::BlockRequested;}
 if record==Record::NotRedirected {Decision::ConditionalIssue} else {Decision::BlockRequested}
}
#[cfg(test)]mod tests{
 use super::*;
 #[test]fn only_queried_clean_can_issue(){for r in [Record::Absent,Record::Null,Record::NullHypotheticalClean,Record::ByOther,Record::Unknown] {assert_eq!(guard(true,true,true,true,true,r),Decision::BlockRequested);}}
 #[test]fn self_cannot_redirect_twice(){for r in [Record::BySelf,Record::PreviouslySelf] {assert_eq!(guard(true,true,true,true,true,r),Decision::NoNewRedirect);}}
 #[test]fn lease_and_life_are_independent(){assert_eq!(guard(true,true,false,true,true,Record::NotRedirected),Decision::BlockRequested);assert_eq!(guard(true,true,true,false,true,Record::NotRedirected),Decision::BlockRequested);}
 #[test]fn scope_unobserved(){assert_eq!(guard(false,true,true,true,true,Record::NotRedirected),Decision::Unobserved);assert_eq!(guard(true,false,true,true,true,Record::NotRedirected),Decision::Unobserved);}
}
