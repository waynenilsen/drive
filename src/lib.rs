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
use libc::{ ENOENT, ENOSYS, c_int };
use time::Timespec;
use fuse::*;
use std::ffi::OsStr;
use std::collections::{HashMap}; 

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
pub struct SafeFS {
	safe : launcher::Launcher,
	ino_cache : Vec<String>, 
	ino_map : HashMap<String, u64>, 
}

impl Filesystem for SafeFS {
    
    /// Initialize filesystem
    /// Called before any other filesystem method.
    fn init (&mut self, _req: &Request) -> Result<(), c_int> {
        Ok(())
    }

    /// Clean up filesystem
    /// Called on filesystem exit.
    fn destroy (&mut self, _req: &Request) {
    }

    /// Look up a directory entry by name and get its attributes.
    fn lookup (&mut self, _req: &Request, _parent: u64, _name: &Path, reply: ReplyEntry) {
		println!("LOOKUP! {:?}", _name); 
		let start_time = time::now().to_timespec();
		
		let path_string = self.full_path_string(_name, _parent).unwrap(); 
		let result = self.safe.listdir(
			10*1000,
			false,
			&path_string
		);
		let t = time::now().to_timespec();
		
		match result {
			Ok(resp) => {
				let attrs = dir_info_to_file_attr(&resp.info, self.ino_from_path(&path_string));
				
				reply.entry(
					&t,
					& attrs,
					0
				);
			},
			Err(_) => {
				reply.error(ENOENT); 
			}
		}
    }

    /// Forget about an inode
    /// The nlookup parameter indicates the number of lookups previously performed on
    /// this inode. If the filesystem implements inode lifetimes, it is recommended that
    /// inodes acquire a single reference on each lookup, and lose nlookup references on
    /// each forget. The filesystem may ignore forget calls, if the inodes don't need to
    /// have a limited lifetime. On unmount it is not guaranteed, that all referenced
    /// inodes will receive a forget message.
    fn forget (&mut self, _req: &Request, _ino: u64, _nlookup: u64) {
    }

    /// Get file attributes
    fn getattr (&mut self, _req: &Request, _ino: u64, reply: ReplyAttr) {
        reply.error(ENOSYS);
    }

    /// Set file attributes
    fn setattr (&mut self, _req: &Request, _ino: u64, _mode: Option<u32>, _uid: Option<u32>, _gid: Option<u32>, _size: Option<u64>, _atime: Option<Timespec>, _mtime: Option<Timespec>, _fh: Option<u64>, _crtime: Option<Timespec>, _chgtime: Option<Timespec>, _bkuptime: Option<Timespec>, _flags: Option<u32>, reply: ReplyAttr) {
        reply.error(ENOSYS);
    }

    /// Read symbolic link
    fn readlink (&mut self, _req: &Request, _ino: u64, reply: ReplyData) {
        reply.error(ENOSYS);
    }

    /// Create file node
    /// Create a regular file, character device, block device, fifo or socket node.
    fn mknod (&mut self, _req: &Request, _parent: u64, _name: &Path, _mode: u32, _rdev: u32, reply: ReplyEntry) {
		println!("MKNOD!"); 
        reply.error(ENOSYS);
    }

    /// Create a directory
    fn mkdir (&mut self, _req: &Request, _parent: u64, _name: &Path, _mode: u32, reply: ReplyEntry) {
		println!("registered INOs : {:#?}", self.ino_map); 
		println!("cached INOs : {:#?}", self.ino_cache); 
		println!("MKDIR! name={:?}, parent_ino={} parent={:?}", _name, _parent, self.path_from_ino(_parent)); 
		let start_time = time::now().to_timespec(); 
		
		let path_string = self.full_path_string(_name, _parent).unwrap(); 
		
		self.safe.mkdir(
			false,
			&path_string,
			true,
			false,
			"".into()
		);
		let t = time::now().to_timespec(); 
		let ino = self.ino_from_path(&path_string);
		
		reply.entry(
			&t ,
			&FileAttr {
				ino: ino,
				size: 13,
				blocks: 1,
				atime: t,
				mtime: t,
				ctime: t,
				crtime: t,
				kind: FileType::Directory,
				perm: 0o644,
				nlink: 1,
				uid: 501,
				gid: 20,
				rdev: 0,
				flags: 0,
			} ,
			0
		); 
    }

    /// Remove a file
    fn unlink (&mut self, _req: &Request, _parent: u64, _name: &Path, reply: ReplyEmpty) {
        reply.error(ENOSYS);
    }

    /// Remove a directory
    fn rmdir (&mut self, _req: &Request, _parent: u64, _name: &Path, reply: ReplyEmpty) {
        reply.error(ENOSYS);
    }

    /// Create a symbolic link
    fn symlink (&mut self, _req: &Request, _parent: u64, _name: &Path, _link: &Path, reply: ReplyEntry) {
        reply.error(ENOSYS);
    }

    /// Rename a file
    fn rename (&mut self, _req: &Request, _parent: u64, _name: &Path, _newparent: u64, _newname: &Path, reply: ReplyEmpty) {
        reply.error(ENOSYS);
    }

    /// Create a hard link
    fn link (&mut self, _req: &Request, _ino: u64, _newparent: u64, _newname: &Path, reply: ReplyEntry) {
        reply.error(ENOSYS);
    }

    /// Open a file
    /// Open flags (with the exception of O_CREAT, O_EXCL, O_NOCTTY and O_TRUNC) are
    /// available in flags. Filesystem may store an arbitrary file handle (pointer, index,
    /// etc) in fh, and use this in other all other file operations (read, write, flush,
    /// release, fsync). Filesystem may also implement stateless file I/O and not store
    /// anything in fh. There are also some flags (direct_io, keep_cache) which the
    /// filesystem may set, to change the way the file is opened. See fuse_file_info
    /// structure in <fuse_common.h> for more details.
    fn open (&mut self, _req: &Request, _ino: u64, _flags: u32, reply: ReplyOpen) {
        reply.opened(0, 0);
    }

    /// Read data
    /// Read should send exactly the number of bytes requested except on EOF or error,
    /// otherwise the rest of the data will be substituted with zeroes. An exception to
    /// this is when the file has been opened in 'direct_io' mode, in which case the
    /// return value of the read system call will reflect the return value of this
    /// operation. fh will contain the value set by the open method, or will be undefined
    /// if the open method didn't set any value.
    fn read (&mut self, _req: &Request, _ino: u64, _fh: u64, _offset: u64, _size: u32, reply: ReplyData) {
        reply.error(ENOSYS);
    }

    /// Write data
    /// Write should return exactly the number of bytes requested except on error. An
    /// exception to this is when the file has been opened in 'direct_io' mode, in
    /// which case the return value of the write system call will reflect the return
    /// value of this operation. fh will contain the value set by the open method, or
    /// will be undefined if the open method didn't set any value.
    fn write (&mut self, _req: &Request, _ino: u64, _fh: u64, _offset: u64, _data: &[u8], _flags: u32, reply: ReplyWrite) {
        reply.error(ENOSYS);
    }

    /// Flush method
    /// This is called on each close() of the opened file. Since file descriptors can
    /// be duplicated (dup, dup2, fork), for one open call there may be many flush
    /// calls. Filesystems shouldn't assume that flush will always be called after some
    /// writes, or that if will be called at all. fh will contain the value set by the
    /// open method, or will be undefined if the open method didn't set any value.
    /// NOTE: the name of the method is misleading, since (unlike fsync) the filesystem
    /// is not forced to flush pending writes. One reason to flush data, is if the
    /// filesystem wants to return write errors. If the filesystem supports file locking
    /// operations (setlk, getlk) it should remove all locks belonging to 'lock_owner'.
    fn flush (&mut self, _req: &Request, _ino: u64, _fh: u64, _lock_owner: u64, reply: ReplyEmpty) {
        reply.error(ENOSYS);
    }

    /// Release an open file
    /// Release is called when there are no more references to an open file: all file
    /// descriptors are closed and all memory mappings are unmapped. For every open
    /// call there will be exactly one release call. The filesystem may reply with an
    /// error, but error values are not returned to close() or munmap() which triggered
    /// the release. fh will contain the value set by the open method, or will be undefined
    /// if the open method didn't set any value. flags will contain the same flags as for
    /// open.
    fn release (&mut self, _req: &Request, _ino: u64, _fh: u64, _flags: u32, _lock_owner: u64, _flush: bool, reply: ReplyEmpty) {
        reply.ok();
    }

    /// Synchronize file contents
    /// If the datasync parameter is non-zero, then only the user data should be flushed,
    /// not the meta data.
    fn fsync (&mut self, _req: &Request, _ino: u64, _fh: u64, _datasync: bool, reply: ReplyEmpty) {
        reply.error(ENOSYS);
    }

    /// Open a directory
    /// Filesystem may store an arbitrary file handle (pointer, index, etc) in fh, and
    /// use this in other all other directory stream operations (readdir, releasedir,
    /// fsyncdir). Filesystem may also implement stateless directory I/O and not store
    /// anything in fh, though that makes it impossible to implement standard conforming
    /// directory stream operations in case the contents of the directory can change
    /// between opendir and releasedir.
    fn opendir (&mut self, _req: &Request, _ino: u64, _flags: u32, reply: ReplyOpen) {
        reply.opened(0, 0);
    }

    /// Read directory
    /// Send a buffer filled using buffer.fill(), with size not exceeding the
    /// requested size. Send an empty buffer on end of stream. fh will contain the
    /// value set by the opendir method, or will be undefined if the opendir method
    /// didn't set any value.
    fn readdir (&mut self, _req: &Request, _ino: u64, _fh: u64, _offset: u64, mut reply: ReplyDirectory) {
        println!("READDIR! {:?}", _ino);
        
		let path = match self.path_from_ino(_ino) {
			Some(p) => p,
			None => {
				reply.error(ENOENT);
				return;
			}
		};
		
        let result = self.safe.listdir(
			10*1000,
			false,
			&path
		);
		
		match result {
			Ok(data) => {
				if _offset==0 {
					let i = 2;
					
					reply.add(_ino, 0, FileType::Directory, ".");
					reply.add(_ino, 1, FileType::Directory, "..");
					
					for subdir in data.sub_directories {
						let full_path = self.full_path_string(&Path::new(&subdir.name), _ino).unwrap(); 
						let current_ino = self.ino_from_path(&full_path); 
						reply.add(current_ino, i, FileType::Directory, subdir.name); 
					}
				}
				
				reply.ok(); 
			},
			Err(e) => {
				reply.error(ENOENT); 
			}
		}
    }

    /// Release an open directory
    /// For every opendir call there will be exactly one releasedir call. fh will
    /// contain the value set by the opendir method, or will be undefined if the
    /// opendir method didn't set any value.
    fn releasedir (&mut self, _req: &Request, _ino: u64, _fh: u64, _flags: u32, reply: ReplyEmpty) {
        reply.ok();
    }

    /// Synchronize directory contents
    /// If the datasync parameter is set, then only the directory contents should
    /// be flushed, not the meta data. fh will contain the value set by the opendir
    /// method, or will be undefined if the opendir method didn't set any value.
    fn fsyncdir (&mut self, _req: &Request, _ino: u64, _fh: u64, _datasync: bool, reply: ReplyEmpty) {
        reply.error(ENOSYS);
    }

    /// Get file system statistics
    fn statfs (&mut self, _req: &Request, _ino: u64, reply: ReplyStatfs) {
        reply.statfs(0, 0, 0, 0, 0, 512, 255, 0);
    }

    /// Set an extended attribute
    fn setxattr (&mut self, _req: &Request, _ino: u64, _name: &OsStr, _value: &[u8], _flags: u32, _position: u32, reply: ReplyEmpty) {
        reply.error(ENOSYS);
    }

    /// Get an extended attribute
    fn getxattr (&mut self, _req: &Request, _ino: u64, _name: &OsStr, reply: ReplyData) {
        // FIXME: If arg.size is zero, the size of the value should be sent with fuse_getxattr_out
        // FIXME: If arg.size is non-zero, send the value if it fits, or ERANGE otherwise
        reply.error(ENOSYS);
    }

    /// List extended attribute names
    fn listxattr (&mut self, _req: &Request, _ino: u64, reply: ReplyEmpty) {
        // FIXME: If arg.size is zero, the size of the attribute list should be sent with fuse_getxattr_out
        // FIXME: If arg.size is non-zero, send the attribute list if it fits, or ERANGE otherwise
        reply.error(ENOSYS);
    }

    /// Remove an extended attribute
    fn removexattr (&mut self, _req: &Request, _ino: u64, _name: &OsStr, reply: ReplyEmpty) {
        reply.error(ENOSYS);
    }

    /// Check file access permissions
    /// This will be called for the access() system call. If the 'default_permissions'
    /// mount option is given, this method is not called. This method is not called
    /// under Linux kernel versions 2.4.x
    fn access (&mut self, _req: &Request, _ino: u64, _mask: u32, reply: ReplyEmpty) {
        reply.error(ENOSYS);
    }

    /// Create and open a file
    /// If the file does not exist, first create it with the specified mode, and then
    /// open it. Open flags (with the exception of O_NOCTTY) are available in flags.
    /// Filesystem may store an arbitrary file handle (pointer, index, etc) in fh,
    /// and use this in other all other file operations (read, write, flush, release,
    /// fsync). There are also some flags (direct_io, keep_cache) which the
    /// filesystem may set, to change the way the file is opened. See fuse_file_info
    /// structure in <fuse_common.h> for more details. If this method is not
    /// implemented or under Linux kernel versions earlier than 2.6.15, the mknod()
    /// and open() methods will be called instead.
    fn create (&mut self, _req: &Request, _parent: u64, _name: &Path, _mode: u32, _flags: u32, reply: ReplyCreate) {
        reply.error(ENOSYS);
    }

    /// Test for a POSIX file lock
    fn getlk (&mut self, _req: &Request, _ino: u64, _fh: u64, _lock_owner: u64, _start: u64, _end: u64, _typ: u32, _pid: u32, reply: ReplyLock) {
        reply.error(ENOSYS);
    }

    /// Acquire, modify or release a POSIX file lock
    /// For POSIX threads (NPTL) there's a 1-1 relation between pid and owner, but
    /// otherwise this is not always the case.  For checking lock ownership,
    /// 'fi->owner' must be used. The l_pid field in 'struct flock' should only be
    /// used to fill in this field in getlk(). Note: if the locking methods are not
    /// implemented, the kernel will still allow file locking to work locally.
    /// Hence these are only interesting for network filesystems and similar.
    fn setlk (&mut self, _req: &Request, _ino: u64, _fh: u64, _lock_owner: u64, _start: u64, _end: u64, _typ: u32, _pid: u32, _sleep: bool, reply: ReplyEmpty) {
        reply.error(ENOSYS);
    }

    /// Map block index within file to block index within device
    /// Note: This makes sense only for block device backed filesystems mounted
    /// with the 'blkdev' option
    fn bmap (&mut self, _req: &Request, _ino: u64, _blocksize: u32, _idx: u64, reply: ReplyBmap) {
        reply.error(ENOSYS);
    }

    /// OS X only: Rename the volume. Set fuse_init_out.flags during init to
    /// FUSE_VOL_RENAME to enable
    #[cfg(target_os = "macos")]
    fn setvolname (&mut self, _req: &Request, _name: &OsStr, reply: ReplyEmpty) {
        reply.error(ENOSYS);
    }

    /// OS X only (undocumented)
    #[cfg(target_os = "macos")]
    fn exchange (&mut self, _req: &Request, _parent: u64, _name: &Path, _newparent: u64, _newname: &Path, _options: u64, reply: ReplyEmpty) {
        reply.error(ENOSYS);
    }

    /// OS X only: Query extended times (bkuptime and crtime). Set fuse_init_out.flags
    /// during init to FUSE_XTIMES to enable
    #[cfg(target_os = "macos")]
    fn getxtimes (&mut self, _req: &Request, _ino: u64, reply: ReplyXTimes) {
        reply.error(ENOSYS);
    }
}

impl SafeFS {
	pub fn new(safe : launcher::Launcher) -> SafeFS {
		let mut ino_cache = Vec::new();
		let mut ino_map = HashMap::new();
		
		ino_cache.push("NEVER".to_owned());
		ino_cache.push("/".to_owned());
		ino_map.insert("/".to_owned(), 1); 
		
		SafeFS {
			safe : safe,
			ino_cache : ino_cache,
			ino_map : ino_map, 
		}
	}
	
	fn ino_from_path(&mut self, path : &String) -> u64 {
		let my_copy = (**path).to_owned(); 
		let my_copy_2 = (*my_copy).to_owned(); 
		
		if self.ino_map.contains_key(path) {
			return *self.ino_map.get(path).unwrap();
		}
		
		self.ino_cache.push(my_copy);
		self.ino_map.insert(my_copy_2, self.ino_cache.len() as u64 - 1);
		self.ino_cache.len() as u64 - 1
	}
	
	fn path_from_ino(&self, ino : u64) -> Option<String> {
		let ino2 = ino as usize; 
		if ino2 < self.ino_cache.len() {
			return Some((*self.ino_cache[ino2]).to_owned());
		}
		None
	}
	
	fn full_path_string(&self, name : &Path, parent_ino : u64) -> Option<String> {
		match self.path_from_ino(parent_ino) {
			Some(p) => Some(
				Path::new(&p)
					.join(name)
					.to_str()
					.unwrap()
					.to_owned()
				),
			None => None
		}
	}
}

fn dir_info_to_file_attr(dir_info : &launcher::DirInfo, ino : u64) -> FileAttr {
	FileAttr {
		ino: ino,
		size: 0,
		blocks: 1,
		atime: Timespec{ sec : dir_info.creation_time_sec, nsec : dir_info.creation_time_nsec as i32 },
		mtime: Timespec{ sec : dir_info.creation_time_sec, nsec : dir_info.creation_time_nsec as i32 },
		ctime: Timespec{ sec : dir_info.creation_time_sec, nsec : dir_info.creation_time_nsec as i32 },
		crtime: Timespec{ sec : dir_info.creation_time_sec, nsec : dir_info.creation_time_nsec as i32 },
		kind: FileType::Directory,
		perm: 0o644,
		nlink: 1,
		uid: 501,
		gid: 20,
		rdev: 0,
		flags: 0,
	}
}


/// Blocking function that mounts the drive based on the mount point (loc) and the 
/// first argument from the launcher command line params
pub fn mount_safe(loc: &str, main_arg : &str) {
	let safe = launcher::Launcher::new(main_arg);
	let options : &[&OsStr] = &[]; 
	let fs = SafeFS::new(safe);
	let path = Path::new(loc); 
	
	fuse::mount(fs, &path, options); 
}
