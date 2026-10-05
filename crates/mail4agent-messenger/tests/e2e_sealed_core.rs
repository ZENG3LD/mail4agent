//! End-to-end test for at-rest sealing: [`MessengerCore::open_sealed`]
//! with a caller-supplied 32-byte [`CoreSecrets::store_seal_key`], driven
//! entirely through the kernel API. A fresh device persists sealed
//! records, and a later restart continues from exactly those records under
//! the same key. A restart under a different key must fail to open loudly,
//! not silently start over with a fresh identity.

use mail4agent_messenger::{CoreConfig, CoreSecrets, DeviceId, Jitter, MessengerCore, RecordKey, SealedRecord, UserId};
use zeroize::Zeroizing;

struct FixedJitter(f64);

impl Jitter for FixedJitter {
    fn next_unit(&mut self) -> f64 {
        self.0
    }
}

fn core_config() -> CoreConfig {
    CoreConfig {
        user_id: UserId::parse("@alice:example.org").expect("valid user id"),
        device_id: DeviceId::parse("DEV1").expect("valid device id"),
        server_name: "example.org".to_string(),
    }
}

fn secrets(key_byte: u8) -> CoreSecrets {
    CoreSecrets { store_seal_key: Some(Zeroizing::new([key_byte; 32])), backup_key: None }
}

#[test]
fn e2e_sealed_core_restart_resumes_from_sealed_records() {
    let mut core = MessengerCore::open_sealed(Vec::new(), secrets(7), core_config(), 0, Box::new(FixedJitter(0.0)))
        .expect("open_sealed succeeds on a brand-new device");

    let first_batch = core
        .take_flush_batch()
        .expect("opening a fresh device dirties at least its own Olm account record");
    assert!(!first_batch.records.is_empty());
    core.ack_flush(first_batch.id);
    assert!(core.take_flush_batch().is_none(), "nothing else pending right after the initial bootstrap flush");

    let records: Vec<SealedRecord> = first_batch.records.clone();

    let mut restarted = MessengerCore::open_sealed(records.clone(), secrets(7), core_config(), 0, Box::new(FixedJitter(0.0)))
        .expect("reopen under the same seal key succeeds");
    assert!(
        restarted.take_flush_batch().is_none(),
        "the persisted account was reused, not silently regenerated with a fresh identity"
    );

    let err = MessengerCore::open_sealed(records, secrets(9), core_config(), 0, Box::new(FixedJitter(0.0)))
        .err()
        .expect("a different seal key must fail to open, not silently start over");
    let message = err.to_string();
    assert!(
        message.contains("codec rejected"),
        "the error names the codec-open failure clearly, not a generic decode error: {message}"
    );
}

#[test]
fn e2e_sealed_core_open_sealed_without_store_seal_key_fails_clearly() {
    let err = MessengerCore::open_sealed(Vec::<SealedRecord>::new(), CoreSecrets::default(), core_config(), 0, Box::new(FixedJitter(0.0)))
        .err()
        .expect("open_sealed with no store_seal_key must not silently proceed unsealed");
    let message = err.to_string();
    assert!(
        message.contains("store_seal_key"),
        "the error tells the caller which field is missing: {message}"
    );
}

#[test]
fn e2e_sealed_core_records_are_illegible_without_the_codec() {
    let mut core = MessengerCore::open_sealed(Vec::new(), secrets(11), core_config(), 0, Box::new(FixedJitter(0.0)))
        .expect("open_sealed succeeds");

    let batch = core.take_flush_batch().expect("the fresh account bootstrap dirtied a record");
    let account_key = RecordKey::new("messenger/DEV1/account");
    let account_record = batch
        .records
        .iter()
        .find(|record| record.key == account_key)
        .expect("the fresh account was persisted under its own key");
    assert!(
        serde_json::from_slice::<serde_json::Value>(&account_record.bytes).is_err(),
        "sealed bytes must not be readable as the plaintext account record"
    );
}
