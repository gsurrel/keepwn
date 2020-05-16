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

extern crate reqwest;
extern crate rpassword;
extern crate zeroize;

#[macro_use]
pub mod api;

use reqwest::blocking::Client;
use reqwest::header;
use reqwest::StatusCode;
use std::panic;
use zeroize::Zeroize;

pub fn pass_check(data_search: &api::PassArg) {
    let mut headers = header::HeaderMap::new();
    headers.insert(
        header::USER_AGENT,
        header::HeaderValue::from_static(api::CHECKPWN_USER_AGENT),
    );
    headers.insert(
        "Add-Padding",
        header::HeaderValue::from_str("true").unwrap(),
    );

    let client = Client::builder().default_headers(headers).build().unwrap();

    let mut hashed_password = api::hash_password(&data_search.password);
    let uri_acc = api::arg_to_api_route(&api::CheckableChoices::PASS, &hashed_password);

    set_checkpwn_panic!(api::errors::NETWORK_ERROR);
    let pass_stat = client.get(&uri_acc).send().unwrap();

    set_checkpwn_panic!(api::errors::DECODING_ERROR);
    let request_status = pass_stat.status();
    let pass_body: String = pass_stat.text().unwrap();

    if api::search_in_range(&pass_body, &hashed_password) {
        api::breach_report(request_status);
    } else {
        api::breach_report(StatusCode::NOT_FOUND);
    }

    // Zero out as this contains a weakly hashed password
    hashed_password.zeroize();
}
