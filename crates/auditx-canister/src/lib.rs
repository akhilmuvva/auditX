use ic_cdk::*;
use candid::{CandidType, Principal};
use serde::Deserialize;
use std::cell::RefCell;
use std::collections::HashMap;

#[derive(CandidType, Deserialize, Clone)]
pub struct AuditRecord {
    pub contract_address: String,
    pub web3_cvss: f32,
    pub web2_cvss: f32,
    pub combined_cvss: f32,
    pub eas_uid: String,
    pub ipfs_cid: String,
    pub badge_token_id: Option<u64>,
    pub timestamp: u64,
    pub chain_count: u32,
    pub auditor: Principal,
}

thread_local! {
    static RECORDS: RefCell<HashMap<String, AuditRecord>> = RefCell::default();
}

#[update]
fn store_audit(contract: String, record: AuditRecord) {
    RECORDS.with(|r| r.borrow_mut().insert(contract, record));
}

#[query]
fn get_audit(contract: String) -> Option<AuditRecord> {
    RECORDS.with(|r| r.borrow().get(&contract).cloned())
}

#[query]
fn get_all() -> Vec<(String, AuditRecord)> {
    RECORDS.with(|r| r.borrow().clone().into_iter().collect())
}

#[query]
fn get_by_cvss(min: f32) -> Vec<(String, AuditRecord)> {
    RECORDS.with(|r| {
        r.borrow()
            .iter()
            .filter(|(_, rec)| rec.combined_cvss >= min)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    })
}

ic_cdk::export_candid!();
