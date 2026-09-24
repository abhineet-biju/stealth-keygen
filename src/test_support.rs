//! Deterministic public fixtures for tests only. Never use this RNG for real keys.

use rand_core::{TryCryptoRng, TryRng};
use std::{collections::VecDeque, fmt};

#[derive(Debug, PartialEq, Eq)]
pub enum TestRngError {
    InjectedFailure,
    Exhausted,
}

impl fmt::Display for TestRngError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for TestRngError {}

pub struct ScriptedRng {
    bytes: VecDeque<u8>,
    pub calls: usize,
    fail_on: Option<usize>,
}

impl ScriptedRng {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into().into(),
            calls: 0,
            fail_on: None,
        }
    }

    pub fn failing_on(mut self, call: usize) -> Self {
        self.fail_on = Some(call);
        self
    }
}

impl TryRng for ScriptedRng {
    type Error = TestRngError;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), Self::Error> {
        self.calls += 1;
        if self.fail_on == Some(self.calls) {
            return Err(TestRngError::InjectedFailure);
        }
        if self.bytes.len() < out.len() {
            return Err(TestRngError::Exhausted);
        }
        for byte in out {
            *byte = self.bytes.pop_front().unwrap();
        }
        Ok(())
    }
}

// Intentionally fake cryptographic randomness, confined to test builds.
impl TryCryptoRng for ScriptedRng {}

pub fn hex<const N: usize>(input: &str) -> [u8; N] {
    assert_eq!(input.len(), 2 * N);
    let mut out = [0; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&input[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

pub fn vector<const N: usize>(key: &str) -> [u8; N] {
    let value = include_str!("../tests/fixtures/v1.txt")
        .lines()
        .filter_map(|line| line.split_once('='))
        .find(|(name, _)| *name == key)
        .unwrap()
        .1;
    hex(value)
}

pub fn identity_rng() -> ScriptedRng {
    ScriptedRng::new(
        [
            vector::<64>("spend_entropy").as_slice(),
            vector::<32>("scan_entropy").as_slice(),
        ]
        .concat(),
    )
}

pub fn payment_rng() -> ScriptedRng {
    ScriptedRng::new(vector::<32>("ephemeral_entropy").to_vec())
}
