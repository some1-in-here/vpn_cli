use std::fs;
use std::ops::Not;
use std::path::{Path};


/// Creates a parent directory if it doesn't exist.
pub fn create_parent_dir_all<P: AsRef<Path>>(path: P) -> Result<(), std::io::Error> {
    let Some(path) = path.as_ref().parent() else {
        return Ok(());
    };

    if fs::exists(path)? {
        return Ok(());
    }

    fs::create_dir_all(&path)?;
    Ok(())
}