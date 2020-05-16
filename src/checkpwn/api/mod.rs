// TODO: currently copied from https://github.com/brycx/checkpwn/,
// TODO:     change to checkpwn when it's usable as a library

// MIT License

// Copyright (c) 2018-2020 brycx

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#[macro_use]
pub mod errors;

use colored::Colorize;
use reqwest::StatusCode;
use sha1::{Digest, Sha1};
use zeroize::Zeroize;

use std::panic;

pub const CHECKPWN_USER_AGENT: &str = "keepwn - check a keepass database against HIBP";

pub enum CheckableChoices {
    PASS,
}

impl CheckableChoices {
    fn get_api_route(&self, search_term: &str) -> String {
        match self {
            CheckableChoices::PASS => {
                format!("https://api.pwnedpasswords.com/range/{}", search_term)
            }
        }
    }
}

pub struct PassArg {
    pub password: String,
}

impl Drop for PassArg {
    fn drop(&mut self) {
        self.password.zeroize()
    }
}

/// Take the user-supplied command-line arguments and make a URL for the HIBP API.
/// If the `pass` argument has been selected, `input_data` needs to be the hashed password.
pub fn arg_to_api_route(arg: &CheckableChoices, input_data: &str) -> String {
    match arg {
        CheckableChoices::PASS => arg.get_api_route(
            // Only send the first 5 chars to the password range API
            &input_data[..5],
        ),
    }
}

/// Find matching key in received set of keys.
pub fn search_in_range(password_range_response: &str, hashed_key: &str) -> bool {
    for line in password_range_response.lines() {
        let pair: Vec<_> = line.split(':').collect();
        // Padded entries always have an occurrence of 0 and should be
        // discarded.
        if *pair.get(1).unwrap() == "0" {
            continue;
        }

        // Each response is truncated to only be the hash, no whitespace, etc.
        // All hashes here have a length of 35, so the useless gets dropped by
        // slicing. Don't include first five characters of own password, as
        // this also is how the HIBP API returns passwords.
        if *pair.get(0).unwrap() == &hashed_key[5..] {
            return true;
        }
    }

    false
}

/// Make a breach report based on StatusCode and print result to terminal.
pub fn breach_report(status_code: StatusCode) -> ((), bool) {
    match status_code {
        StatusCode::NOT_FOUND => (println!("{}", "password not breached ✅".green()), false),
        StatusCode::OK => (println!("{}", "password breached ⚠️".red()), true),
        _ => {
            set_checkpwn_panic!(errors::STATUSCODE_ERROR);
            panic!();
        }
    }
}

/// Return SHA1 digest of string.
pub fn hash_password(password: &str) -> String {
    let mut sha_digest = Sha1::default();
    sha_digest.input(password.as_bytes());
    // Make uppercase for easier comparison with
    // HIBP API response
    hex::encode(sha_digest.result()).to_uppercase()
}
