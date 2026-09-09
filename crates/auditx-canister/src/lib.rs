use candid::{CandidType, Principal};
use ic_cdk::*;
use serde::Deserialize;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

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
    static AUTHORIZED_AUDITORS: RefCell<HashSet<Principal>> = RefCell::default();
}

fn valid_record(contract: &str, record: &AuditRecord) -> bool {
    !contract.trim().is_empty()
        && contract.len() <= 256
        && !record.contract_address.trim().is_empty()
        && record.contract_address.len() <= 256
        && record.eas_uid.len() <= 256
        && record.ipfs_cid.len() <= 256
        && record.web3_cvss.is_finite()
        && record.web2_cvss.is_finite()
        && record.combined_cvss.is_finite()
        && (0.0..=10.0).contains(&record.web3_cvss)
        && (0.0..=10.0).contains(&record.web2_cvss)
        && (0.0..=10.0).contains(&record.combined_cvss)
}

#[update]
fn store_audit(contract: String, mut record: AuditRecord) -> Result<(), String> {
    let caller = caller();
    if !ic_cdk::api::is_controller(&caller)
        && !AUTHORIZED_AUDITORS.with(|auditors| auditors.borrow().contains(&caller))
    {
        return Err("Caller is not an authorized auditor".to_string());
    }
    if record.auditor != caller {
        return Err("Audit record auditor must match the caller".to_string());
    }
    if !valid_record(&contract, &record) {
        return Err("Audit record contains invalid fields".to_string());
    }
    RECORDS.with(|records| {
        let mut records = records.borrow_mut();
        if records.contains_key(&contract) {
            return Err("An audit already exists for this contract".to_string());
        }
        record.contract_address = contract.clone();
        records.insert(contract, record);
        Ok(())
    })
}

#[update]
fn authorize_auditor(auditor: Principal) -> Result<(), String> {
    if !ic_cdk::api::is_controller(&caller()) {
        return Err("Only a canister controller can authorize auditors".to_string());
    }
    AUTHORIZED_AUDITORS.with(|auditors| {
        auditors.borrow_mut().insert(auditor);
    });
    Ok(())
}

#[update]
fn revoke_auditor(auditor: Principal) -> Result<(), String> {
    if !ic_cdk::api::is_controller(&caller()) {
        return Err("Only a canister controller can revoke auditors".to_string());
    }
    AUTHORIZED_AUDITORS.with(|auditors| {
        auditors.borrow_mut().remove(&auditor);
    });
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> AuditRecord {
        AuditRecord {
            contract_address: "0xcontract".to_string(),
            web3_cvss: 5.0,
            web2_cvss: 4.0,
            combined_cvss: 4.5,
            eas_uid: "uid".to_string(),
            ipfs_cid: "cid".to_string(),
            badge_token_id: None,
            timestamp: 1,
            chain_count: 1,
            auditor: Principal::anonymous(),
        }
    }

    #[test]
    fn rejects_invalid_inputs() {
        assert!(valid_record("0xcontract", &record()));
        assert!(!valid_record("", &record()));
        let mut invalid = record();
        invalid.combined_cvss = 10.1;
        assert!(!valid_record("0xcontract", &invalid));
    }
}
