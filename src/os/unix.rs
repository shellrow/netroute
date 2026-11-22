use std::{collections::HashMap, ffi::CStr};

#[derive(Default)]
pub(super) struct InterfaceNames(HashMap<u32, Option<String>>);

impl InterfaceNames {
    pub(super) fn lookup(&mut self, index: u32) -> Option<String> {
        self.0
            .entry(index)
            .or_insert_with(|| {
                let mut name = [0; libc::IF_NAMESIZE];
                // if_indextoname writes a NUL-terminated name on success.
                let result = unsafe { libc::if_indextoname(index, name.as_mut_ptr()) };
                if result.is_null() {
                    return None;
                }
                Some(
                    unsafe { CStr::from_ptr(name.as_ptr()) }
                        .to_string_lossy()
                        .into_owned(),
                )
            })
            .clone()
    }
}
