extern crate fuse;

extern crate drive; 

use drive::mount_safe; 

pub fn main() {
	println!("\n======================================================\n");
    println!("App: Begin test app...");
    let mut arg_vec = Vec::with_capacity(3);
    for it in ::std::env::args() {
        arg_vec.push(it);
    }

    if arg_vec.len() < 3 {
        println!("App: Wrong number of command line agruments. This app is only meant to be started by Launcher.");
        return
    }

    // Read the command line argument that Launcher starts this application with
    let main_arg = arg_vec[2].clone();
    
    let mountpoint = "/mnt/fuse-test"; 
    mount_safe(mountpoint, &*main_arg); 
}
