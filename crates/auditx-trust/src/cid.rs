use sha2::{Sha256, Digest};
use bs58;

pub fn generate_cid_v0(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash_result = hasher.finalize();

    // multihash prefix for sha2-256 (0x12) and length 32 (0x20)
    let mut prefix_bytes = vec![0x12, 0x20];
    prefix_bytes.extend_from_slice(&hash_result);

    bs58::encode(prefix_bytes).into_string()
}
