// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.                                                                 */

//!#Drive
//!A cross platform virtual file-system in userspace (drive) that will appear as a regular drive on the operating system.
//! The interface is a POSIX-like API and this is exposed in every OS. May include a webdav interface where possible.
//!IOS and Android etc. may require a driverless option and will require further consideration (webdav ?) to provide the
//! same cross platform/OS compatibility.
//!This drive can provide a blocking call to be used as a stand alone application or a threaded call to enable a drive to be mounted from any application.
/*
#![doc(html_logo_url =
           "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://maidsafe.github.io/drive/")]

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, raw_pointer_derive, stable_features,
        unconditional_recursion, unknown_lints, unsafe_code, unused, unused_allocation,
        unused_attributes, unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results, variant_size_differences)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations)]
*/
extern crate fuse;
extern crate libc;
extern crate time;


extern crate regex;
extern crate byteorder;
extern crate bufstream;
extern crate sodiumoxide;
extern crate rustc_serialize;

mod stream;
mod launcher;

use launcher::*; 
use std::env;
use std::path::Path;
use libc::ENOENT;
use time::Timespec;
use fuse::{FileType, FileAttr, Filesystem, Request, ReplyData, ReplyEntry, ReplyAttr, ReplyDirectory};

const TTL: Timespec = Timespec { sec: 1, nsec: 0 };                 // 1 second

const CREATE_TIME: Timespec = Timespec { sec: 1381237736, nsec: 0 };    // 2013-10-08 08:56

const HELLO_DIR_ATTR: FileAttr = FileAttr {
    ino: 1,
    size: 0,
    blocks: 0,
    atime: CREATE_TIME,
    mtime: CREATE_TIME,
    ctime: CREATE_TIME,
    crtime: CREATE_TIME,
    kind: FileType::Directory,
    perm: 0o755,
    nlink: 2,
    uid: 501,
    gid: 20,
    rdev: 0,
    flags: 0,
};

const HELLO_TXT_CONTENT: &'static str = "Hello World!\n";

const HELLO_TXT_ATTR: FileAttr = FileAttr {
    ino: 2,
    size: 13,
    blocks: 1,
    atime: CREATE_TIME,
    mtime: CREATE_TIME,
    ctime: CREATE_TIME,
    crtime: CREATE_TIME,
    kind: FileType::RegularFile,
    perm: 0o644,
    nlink: 1,
    uid: 501,
    gid: 20,
    rdev: 0,
    flags: 0,
};

#[allow(unused)] // why do i need this, it is being used in the test below..
struct HelloFS {
	symm_key : i64,
	symm_nonce : i64,
	ipc_stream : i64,
}

impl Filesystem for HelloFS {
    fn lookup (&mut self, _req: &Request, parent: u64, name: &Path, reply: ReplyEntry) {
        if parent == 1 && name.to_str() == Some("hello.txt") {
            reply.entry(&TTL, &HELLO_TXT_ATTR, 0);
        } else {
            reply.error(ENOENT);
        }
    }

    fn getattr (&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        match ino {
            1 => reply.attr(&TTL, &HELLO_DIR_ATTR),
            2 => reply.attr(&TTL, &HELLO_TXT_ATTR),
            _ => reply.error(ENOENT),
        }
    }

    fn read (&mut self, _req: &Request, ino: u64, _fh: u64, offset: u64, _size: u32, reply: ReplyData) {
        if ino == 2 {
            reply.data(&HELLO_TXT_CONTENT.as_bytes()[offset as usize..]);
        } else {
            reply.error(ENOENT);
        }
    }

    fn readdir (&mut self, _req: &Request, ino: u64, _fh: u64, offset: u64, mut reply: ReplyDirectory) {
        if ino == 1 {
            if offset == 0 {
                reply.add(1, 0, FileType::Directory, ".");
                reply.add(1, 1, FileType::Directory, "..");
                reply.add(2, 2, FileType::RegularFile, "hello.txt");
            }
            reply.ok();
        } else {
            reply.error(ENOENT);
        }
    }
}

impl HelloFS {
}

#[test]
fn test_hello () {
    let mountpoint = "/mnt/fuse-test"; 
    fuse::mount(HelloFS, &mountpoint, &[]);
}
