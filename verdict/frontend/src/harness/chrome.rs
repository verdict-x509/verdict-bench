use std::path::PathBuf;
use std::process;

use chrono::{TimeZone, Utc};

use super::common::*;
use crate::error::*;

pub struct ChromeHarness {
    pub repo: String,
    pub faketime_lib: String,
    pub debug: bool,
}

impl Harness for ChromeHarness {
    /// Spawns a child process to run cert_bench
    fn spawn(&self, roots_path: &str, timestamp: u64) -> Result<Box<dyn Instance>, Error> {
        let mut bin_path = PathBuf::from(&self.repo);
        bin_path.extend([ "src", "out", "Release", "cert_bench" ]);

        let fake_time = Utc.timestamp_opt(timestamp as i64, 0).unwrap()
            .format("%Y-%m-%d %H:%M:%S").to_string();

        // Check `args.faketime_lib` exists
        if !PathBuf::from(&self.faketime_lib).exists() {
            return Err(Error::LibFakeTimeNotFound(self.faketime_lib.clone()));
        }

        if !bin_path.exists() {
            return Err(Error::ChromeRepoNotFound(bin_path.display().to_string()));
        }

        let mut cmd = process::Command::new(bin_path);
        cmd.arg(roots_path)
            // Use libfaketime to change the validation time
            .env("LD_PRELOAD", &self.faketime_lib)
            .env("FAKETIME", &format!("@{}", fake_time))
            .stdin(process::Stdio::piped())
            .stdout(process::Stdio::piped());

        if !self.debug {
            cmd.stderr(process::Stdio::null());
        };

        Ok(Box::new(CommonBenchInstance::new(cmd.spawn()?, timestamp)?))
    }
}
