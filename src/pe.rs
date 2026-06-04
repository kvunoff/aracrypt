use std::mem;

const MZ_SIGNATURE: &[u8] = b"MZ";
const PE_SIGNATURE: &[u8] = b"PE\0\0";
const PE_SIGNATURE_SIZE: usize = 4;

const OPTIONAL_HEADER_MAGIC_PE32: u16 = 0x10b;
#[allow(dead_code)]
const OPTIONAL_HEADER_MAGIC_PE64: u16 = 0x20b;

const IMAGE_SUBSYSTEM_WINDOWS_GUI: u16 = 2;
const IMAGE_SUBSYSTEM_WINDOWS_CUI: u16 = 3;

const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
const IMAGE_FILE_DLL: u16 = 0x2000;

const CLR_RUNTIME_HEADER_INDEX: usize = 14;

#[repr(C, packed)]
pub struct MzHeader {
    pub signature: [u8; 2],
    pub data: [u8; 0x3a],
    pub ptr_pe: u32,
}

#[repr(C, packed)]
pub struct CoffHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[repr(C, packed)]
pub struct OptionalStandardHeader32 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
}

#[repr(C, packed)]
pub struct OptionalStandardHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
}

#[repr(C, packed)]
pub struct OptionalWindowsHeader32 {
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_os_version: u16,
    pub minor_os_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

#[repr(C, packed)]
pub struct OptionalWindowsHeader64 {
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_os_version: u16,
    pub minor_os_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

#[repr(C, packed)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

pub struct PeData {
    pub image_base: u64,
    pub size_of_image: u32,
    pub is_gui: bool,
    pub is_64bit: bool,
    pub resources: Option<Vec<u8>>,
}

const IMAGE_SIZEOF_SHORT_NAME: usize = 8;

#[repr(C, packed)]
struct ImageSectionHeader {
    name: [u8; IMAGE_SIZEOF_SHORT_NAME],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_linenumbers: u32,
    number_of_relocations: u16,
    number_of_linenumbers: u16,
    characteristics: u32,
}

fn read_struct<T>(data: &[u8], offset: usize) -> Option<&T> {
    if offset + mem::size_of::<T>() > data.len() {
        return None;
    }
    unsafe { Some(&*(data.as_ptr().add(offset) as *const T)) }
}

fn verify_mz(data: &[u8]) -> Option<u32> {
    let mz: &MzHeader = read_struct(data, 0)?;
    if &mz.signature != MZ_SIGNATURE {
        eprintln!("[!] No valid MZ signature");
        return None;
    }
    Some(mz.ptr_pe)
}

fn verify_pe(data: &[u8], pe_offset: u32) -> Option<usize> {
    let ptr = pe_offset as usize;
    if ptr + PE_SIGNATURE_SIZE > data.len() {
        eprintln!("[!] Pointer to PE in MZ header points to nowhere");
        return None;
    }
    if pe_offset == 0 {
        eprintln!("[!] Pointer to PE in MZ header is null");
        return None;
    }
    if &data[ptr..ptr + PE_SIGNATURE_SIZE] != PE_SIGNATURE {
        eprintln!("[!] No valid PE signature found");
        return None;
    }
    Some(ptr + PE_SIGNATURE_SIZE)
}

pub fn get_coff_header(data: &[u8]) -> Option<&CoffHeader> {
    if data.len() < mem::size_of::<MzHeader>() {
        eprintln!("[!] No valid executable");
        return None;
    }
    let pe_offset = verify_mz(data)?;
    let coff_offset = verify_pe(data, pe_offset)?;
    read_struct::<CoffHeader>(data, coff_offset)
}

pub fn is_executable(coff: &CoffHeader) -> bool {
    if coff.characteristics & IMAGE_FILE_EXECUTABLE_IMAGE == 0 {
        eprintln!("[!] File is not an executable image");
        return false;
    }
    if coff.characteristics & IMAGE_FILE_DLL != 0 {
        eprintln!("[!] File is a DLL, aborting");
        return false;
    }
    true
}

pub fn is_pe32(data: &[u8], coff_header: &CoffHeader) -> bool {
    let off = coff_header as *const _ as usize - data.as_ptr() as usize + mem::size_of::<CoffHeader>();
    let osh: &OptionalStandardHeader32 = match read_struct(data, off) {
        Some(val) => val,
        None => return false,
    };
    osh.magic == OPTIONAL_HEADER_MAGIC_PE32
}

pub fn is_gui_application(subsystem: u16) -> bool {
    match subsystem {
        IMAGE_SUBSYSTEM_WINDOWS_GUI => true,
        IMAGE_SUBSYSTEM_WINDOWS_CUI => false,
        _ => {
            eprintln!("[*] Unknown subsystem 0x{:x}, treating as GUI", subsystem);
            true
        }
    }
}

pub fn get_osh32<'a>(data: &'a [u8], coff: &CoffHeader) -> Option<&'a OptionalStandardHeader32> {
    let off = coff as *const _ as usize - data.as_ptr() as usize + mem::size_of::<CoffHeader>();
    read_struct(data, off)
}

pub fn get_osh64<'a>(data: &'a [u8], coff: &CoffHeader) -> Option<&'a OptionalStandardHeader64> {
    let off = coff as *const _ as usize - data.as_ptr() as usize + mem::size_of::<CoffHeader>();
    read_struct(data, off)
}

pub fn get_owh32<'a>(data: &'a [u8], osh: &OptionalStandardHeader32) -> Option<&'a OptionalWindowsHeader32> {
    let off = osh as *const _ as usize - data.as_ptr() as usize + mem::size_of::<OptionalStandardHeader32>();
    read_struct(data, off)
}

pub fn get_owh64<'a>(data: &'a [u8], osh: &OptionalStandardHeader64) -> Option<&'a OptionalWindowsHeader64> {
    let off = osh as *const _ as usize - data.as_ptr() as usize + mem::size_of::<OptionalStandardHeader64>();
    read_struct(data, off)
}

pub fn get_idd32<'a>(data: &'a [u8], owh: &OptionalWindowsHeader32) -> Option<&'a [ImageDataDirectory]> {
    let off = owh as *const _ as usize - data.as_ptr() as usize + mem::size_of::<OptionalWindowsHeader32>();
    let count = owh.number_of_rva_and_sizes as usize;
    let end = off + count * mem::size_of::<ImageDataDirectory>();
    if end > data.len() {
        return None;
    }
    unsafe {
        Some(std::slice::from_raw_parts(
            data.as_ptr().add(off) as *const ImageDataDirectory,
            count,
        ))
    }
}

pub fn get_idd64<'a>(data: &'a [u8], owh: &OptionalWindowsHeader64) -> Option<&'a [ImageDataDirectory]> {
    let off = owh as *const _ as usize - data.as_ptr() as usize + mem::size_of::<OptionalWindowsHeader64>();
    let count = owh.number_of_rva_and_sizes as usize;
    let end = off + count * mem::size_of::<ImageDataDirectory>();
    if end > data.len() {
        return None;
    }
    unsafe {
        Some(std::slice::from_raw_parts(
            data.as_ptr().add(off) as *const ImageDataDirectory,
            count,
        ))
    }
}

pub fn is_dotnet(data: &[u8], coff: &CoffHeader) -> bool {
    let pe32 = is_pe32(data, coff);

    if pe32 {
        if let Some(osh) = get_osh32(data, coff) {
            if let Some(owh) = get_owh32(data, osh) {
                if let Some(idds) = get_idd32(data, owh) {
                    if idds.len() > CLR_RUNTIME_HEADER_INDEX {
                        let idd = &idds[CLR_RUNTIME_HEADER_INDEX];
                        if idd.virtual_address != 0 && idd.size != 0 {
                            return true;
                        }
                    }
                }
            }
        }
    } else {
        if let Some(osh) = get_osh64(data, coff) {
            if let Some(owh) = get_owh64(data, osh) {
                if let Some(idds) = get_idd64(data, owh) {
                    if idds.len() > CLR_RUNTIME_HEADER_INDEX {
                        let idd = &idds[CLR_RUNTIME_HEADER_INDEX];
                        if idd.virtual_address != 0 && idd.size != 0 {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

pub fn parse_pe(data: &[u8]) -> Option<PeData> {
    let coff = get_coff_header(data)?;
    if !is_executable(coff) {
        return None;
    }
    if is_dotnet(data, coff) {
        eprintln!("[!] Input file appears to be a .NET executable, aborting");
        return None;
    }

    let pe32 = is_pe32(data, coff);

    let (image_base, size_of_image, subsystem) = if pe32 {
        let osh = get_osh32(data, coff)?;
        let owh = get_owh32(data, osh)?;
        (owh.image_base as u64, owh.size_of_image, owh.subsystem)
    } else {
        let osh = get_osh64(data, coff)?;
        let owh = get_owh64(data, osh)?;
        (owh.image_base, owh.size_of_image, owh.subsystem)
    };

    let resources = extract_resources(data, coff);

    Some(PeData {
        image_base,
        size_of_image,
        is_gui: is_gui_application(subsystem),
        is_64bit: !pe32,
        resources,
    })
}

fn section_headers_offset(data: &[u8], coff: &CoffHeader) -> usize {
    let coff_off = coff as *const _ as usize - data.as_ptr() as usize;
    coff_off + mem::size_of::<CoffHeader>() + coff.size_of_optional_header as usize
}

fn extract_resources(data: &[u8], coff: &CoffHeader) -> Option<Vec<u8>> {
    let hdr_off = section_headers_offset(data, coff);
    let count = coff.number_of_sections as usize;

    for i in 0..count {
        let off = hdr_off + i * mem::size_of::<ImageSectionHeader>();
        let section: &ImageSectionHeader = read_struct(data, off)?;

        let name_end = section.name.iter().position(|&b| b == 0).unwrap_or(IMAGE_SIZEOF_SHORT_NAME);
        let name = std::str::from_utf8(&section.name[..name_end]).unwrap_or("");

        if name == ".rsrc" && section.size_of_raw_data > 0 {
            let start = section.pointer_to_raw_data as usize;
            let size = section.size_of_raw_data as usize;
            if start + size <= data.len() {
                return Some(data[start..start + size].to_vec());
            }
        }
    }
    None
}
