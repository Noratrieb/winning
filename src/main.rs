use std::{
    ffi::CStr,
    fmt::Debug,
    io::{self, Write},
    str::Utf8Error,
};

use binrw::{BinRead, BinWrite};
use color_eyre::{
    Result,
    eyre::{Context, bail},
};

const MSDOS_STUB: &[u8] = include_bytes!("msdos-stub.bin");

#[derive(Debug, BinRead, BinWrite)]
#[br(little)]
#[bw(little)]
#[repr(C)]
struct CoffHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    #[br(map = |val: u16| Characteristics::from_bits_retain(val))]
    #[bw(map = |val| val.bits())]
    characteristics: Characteristics,
}

bitflags::bitflags! {
    #[derive(Debug)]
    #[repr(C)]
    pub struct Characteristics: u16 {
        const IMAGE_FILE_RELOCS_STRIPPED = 0x0001; // Image only, Windows CE, and Microsoft Windows NT and later. This indicates that the file does not contain base relocations and must therefore be loaded at its preferred base address. If the base address is not available, the loader reports an error. The default behavior of the linker is to strip base relocations from executable (EXE) files.
        const IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002; // Image only. This indicates that the image file is valid and can be run. If this flag is not set, it indicates a linker error.
        const IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004; // COFF line numbers have been removed. This flag is deprecated and should be zero.
        const IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008; // COFF symbol table entries for local symbols have been removed. This flag is deprecated and should be zero.
        const IMAGE_FILE_AGGRESSIVE_WS_TRIM = 0x0010; // Obsolete. Aggressively trim working set. This flag is deprecated for Windows 2000 and later and must be zero.
        const IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020; // Application can handle > 2-GB addresses.
        const IMAGE_FILE_BYTES_REVERSED_LO = 0x0080; // Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory. This flag is deprecated and should be zero.
        const IMAGE_FILE_32BIT_MACHINE = 0x0100; // Machine is based on a 32-bit-word architecture.
        const IMAGE_FILE_DEBUG_STRIPPED = 0x0200; // Debugging information is removed from the image file.
        const IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400; // If the image is on removable media, fully load it and copy it to the swap file.
        const IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800; // If the image is on network media, fully load it and copy it to the swap file.
        const IMAGE_FILE_SYSTEM = 0x1000; // The image file is a system file, not a user program.
        const IMAGE_FILE_DLL = 0x2000; // The image file is a dynamic-link library (DLL). Such files are considered executable files for almost all purposes, although they cannot be directly run.
        const IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000; // The file should be run only on a uniprocessor machine.
        const IMAGE_FILE_BYTES_REVERSED_HI = 0x8000; // Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero.
    }
}

#[derive(BinWrite)]
#[bw(little)]
#[bw(magic = b"\x0b\x02")]
#[repr(C)]
struct OptionalHeader {
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    // Windows extension
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    check_sum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    sizeof_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    // Data directories
    export_table: DataDirectory,
    import_table: DataDirectory,
    resource_table: DataDirectory,
    exception_table: DataDirectory,
    certificate_table: DataDirectory,
    base_relocation_table: DataDirectory,
    debug: DataDirectory,
    architecture: DataDirectory,
    global_ptr: DataDirectory,
    tls_table: DataDirectory,
    load_config_table: DataDirectory,
    bound_import: DataDirectory,
    iat: DataDirectory,
    delay_import_descriptor: DataDirectory,
    clr_runtime_header: DataDirectory,
    _reserved: DataDirectory,
}

#[derive(Default, BinWrite)]
#[bw(little)]
#[repr(C)]
struct DataDirectory {
    virtual_address: u32,
    size: u32,
}

bitflags::bitflags! {
    #[derive(Debug)]
    #[repr(C)]
    struct SectionFlags: u32 {
     /// The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.
    const IMAGE_SCN_TYPE_NO_PAD = 0x00000008;
     /// The section contains executable code.
    const IMAGE_SCN_CNT_CODE = 0x00000020;
     /// The section contains initialized data.
    const IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040;
     /// The section contains uninitialized data.
    const IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080;
     /// Reserved for future use.
    const IMAGE_SCN_LNK_OTHER = 0x00000100;
     /// The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
    const IMAGE_SCN_LNK_INFO = 0x00000200;
     /// The section will not become part of the image. This is valid only for object files.
    const IMAGE_SCN_LNK_REMOVE = 0x00000800;
     /// The section contains COMDAT data. For more information, see COMDAT Sections (Object Only). This is valid only for object files.
    const IMAGE_SCN_LNK_COMDAT = 0x00001000;
     /// The section contains data referenced through the global pointer (GP).
    const IMAGE_SCN_GPREL = 0x00008000;
     /// Reserved for future use.
    const IMAGE_SCN_MEM_PURGEABLE = 0x00020000;
     /// Reserved for future use.
    const IMAGE_SCN_MEM_16BIT = 0x00020000;
     /// Reserved for future use.
    const IMAGE_SCN_MEM_LOCKED = 0x00040000;
     /// Reserved for future use.
    const IMAGE_SCN_MEM_PRELOAD = 0x00080000;
     /// Align data on a 1-byte boundary. Valid only for object files.
    const IMAGE_SCN_ALIGN_1BYTES = 0x00100000;
     /// Align data on a 2-byte boundary. Valid only for object files.
    const IMAGE_SCN_ALIGN_2BYTES = 0x00200000;
     /// Align data on a 4-byte boundary. Valid only for object files.
    const IMAGE_SCN_ALIGN_4BYTES = 0x00300000;
     /// Align data on an 8-byte boundary. Valid only for object files.
    const IMAGE_SCN_ALIGN_8BYTES = 0x00400000;
     /// Align data on a 16-byte boundary. Valid only for object files.
    const IMAGE_SCN_ALIGN_16BYTES = 0x00500000;
     /// Align data on a 32-byte boundary. Valid only for object files.
    const IMAGE_SCN_ALIGN_32BYTES = 0x00600000;
     /// Align data on a 64-byte boundary. Valid only for object files.
    const IMAGE_SCN_ALIGN_64BYTES = 0x00700000;
     /// Align data on a 128-byte boundary. Valid only for object files.
    const IMAGE_SCN_ALIGN_128BYTES = 0x00800000;
     /// Align data on a 256-byte boundary. Valid only for object files.
    const IMAGE_SCN_ALIGN_256BYTES = 0x00900000;
     /// Align data on a 512-byte boundary. Valid only for object files.
    const IMAGE_SCN_ALIGN_512BYTES = 0x00A00000;
     /// Align data on a 1024-byte boundary. Valid only for object files.
    const IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000;
     /// Align data on a 2048-byte boundary. Valid only for object files.
    const IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000;
     /// Align data on a 4096-byte boundary. Valid only for object files.
    const IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000;
     /// Align data on an 8192-byte boundary. Valid only for object files.
    const IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000;
     /// The section contains extended relocations.
    const IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000;
    /// The section can be discarded as needed.
    const IMAGE_SCN_MEM_DISCARDABLE = 0x02000000;
    /// The section cannot be cached.
    const IMAGE_SCN_MEM_NOT_CACHED = 0x04000000;
    /// The section is not pageable.
    const IMAGE_SCN_MEM_NOT_PAGED = 0x08000000;
    /// The section can be shared in memory.
    const IMAGE_SCN_MEM_SHARED = 0x10000000;
    /// The section can be executed as code.
    const IMAGE_SCN_MEM_EXECUTE = 0x20000000;
     /// The section can be read.
    const IMAGE_SCN_MEM_READ = 0x40000000;
     /// The section can be written to.
    const IMAGE_SCN_MEM_WRITE = 0x80000000;
    }
}

const IMAGE_SUBSYSTEM_WINDOWS_CUI: u16 = 3;

#[derive(Debug, BinRead, BinWrite)]
#[br(little)]
#[bw(little)]
#[repr(C)]
struct SectionHeader {
    #[br(try_map = |val: [u8; 8]| parse_section_header_name(val))]
    #[bw(map = |val| encode_section_header_name(val))]
    name: String,
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_linenumbers: u32,
    number_of_relocations: u16,
    number_of_linenumbers: u16,
    #[br(map = |val: u32| SectionFlags::from_bits_retain(val))]
    #[bw(map = |val| val.bits())]
    characteristics: SectionFlags,
}

const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

#[derive(Debug, BinRead)]
#[br(little)]
#[repr(C)]
struct SymbolTableEntry {
    name: SymbolName,
    value: u32,
    section_number: u16,
    r#type: u16,
    storage_class: u8,
    number_of_aux_symbols: u8,
}

#[derive(BinRead)]
#[br(little)]
#[repr(C)]
struct SymbolName {
    bytes: [u8; 8],
}

enum SymbolNameRepr {
    Short(String),
    Long(u32),
}

impl SymbolName {
    fn repr(&self) -> Result<SymbolNameRepr, Utf8Error> {
        if self.bytes[..4].iter().all(|&v| v == 0) {
            Ok(SymbolNameRepr::Long(u32::from_le_bytes(
                self.bytes[4..].try_into().unwrap(),
            )))
        } else {
            Ok(SymbolNameRepr::Short(parse_section_header_name(
                self.bytes,
            )?))
        }
    }
}

impl Debug for SymbolName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.repr() {
            Ok(SymbolNameRepr::Short(name)) => write!(f, "{name:?}"),
            Ok(SymbolNameRepr::Long(offset)) => f
                .debug_struct("SymbolName")
                .field("offset", &offset)
                .finish(),
            Err(err) => f.debug_struct("SymbolName").field("err", &err).finish(),
        }
    }
}

fn main() -> Result<()> {
    let objects = std::env::args().skip(1);

    for obj in objects {
        process_object(&obj).wrap_err_with(|| format!("reading {obj}"))?;
    }

    Ok(())
}

fn process_object(path: &str) -> Result<()> {
    let mut outfile_buf = Vec::<u8>::new();
    let outfile = &mut io::Cursor::new(&mut outfile_buf);

    let file = std::fs::read(&path)?;
    let header = CoffHeader::read(&mut io::Cursor::new(&file))?;
    dbg!(&header);

    let string_table_start = header.pointer_to_symbol_table
        + header.number_of_symbols * 18;

    if header.machine != IMAGE_FILE_MACHINE_AMD64 {
        bail!("object file is not x86-64");
    }
    if header.size_of_optional_header > 0 {
        bail!("COFF object has optional header");
    }

    outfile.write_all(MSDOS_STUB)?;

    CoffHeader {
        machine: IMAGE_FILE_MACHINE_AMD64,
        number_of_sections: 0,
        time_date_stamp: 0,
        pointer_to_symbol_table: 0,
        number_of_symbols: 0,
        size_of_optional_header: size_of::<OptionalHeader>().try_into().unwrap(),
        characteristics: Characteristics::IMAGE_FILE_EXECUTABLE_IMAGE,
    }
    .write(outfile)?;

    OptionalHeader {
        major_linker_version: 1,
        minor_linker_version: 1,
        size_of_code: 0,
        size_of_initialized_data: 0,
        size_of_uninitialized_data: 0,
        address_of_entry_point: 0,
        base_of_code: 0,
        image_base: 0,
        section_alignment: 8,
        file_alignment: 8,
        major_operating_system_version: 1,
        minor_operating_system_version: 1,
        major_image_version: 1,
        minor_image_version: 1,
        major_subsystem_version: 1,
        minor_subsystem_version: 1,
        win32_version_value: 0,
        size_of_image: 0,
        size_of_headers: 0,
        check_sum: 0,
        subsystem: IMAGE_SUBSYSTEM_WINDOWS_CUI,
        dll_characteristics: 0,
        size_of_stack_reserve: 1 << 20,
        size_of_stack_commit: 1 << 10,
        size_of_heap_reserve: 0,
        sizeof_heap_commit: 0,
        loader_flags: 0,
        number_of_rva_and_sizes: 16,
        export_table: DataDirectory::default(),
        import_table: DataDirectory::default(),
        resource_table: DataDirectory::default(),
        exception_table: DataDirectory::default(),
        certificate_table: DataDirectory::default(),
        base_relocation_table: DataDirectory::default(),
        debug: DataDirectory::default(),
        architecture: DataDirectory::default(),
        global_ptr: DataDirectory::default(),
        tls_table: DataDirectory::default(),
        load_config_table: DataDirectory::default(),
        bound_import: DataDirectory::default(),
        iat: DataDirectory::default(),
        delay_import_descriptor: DataDirectory::default(),
        clr_runtime_header: DataDirectory::default(),
        _reserved: DataDirectory::default(),
    }
    .write(outfile)?;

    let cursor = &mut io::Cursor::new(&file);
    cursor.set_position(size_of::<CoffHeader>() as u64);

    for _ in 0..header.number_of_sections {
        let section = SectionHeader::read(cursor)?;
        let after_section_pos = cursor.position();

        dbg!(&section);

        cursor.set_position(after_section_pos);
    }

    cursor.set_position(header.pointer_to_symbol_table.into());
    let mut remaining_aux = 0;
    for _ in 0..header.number_of_symbols {
        let sym = SymbolTableEntry::read(cursor)?;
        let pos = cursor.position();

        if remaining_aux > 0 {
            remaining_aux -= 1;
            eprintln!("                            AUX {sym:?}");
            continue;
        }

        remaining_aux = sym.number_of_aux_symbols;

        let name = match sym.name.repr()? {
            SymbolNameRepr::Short(name) => name,
            SymbolNameRepr::Long(offset) => {
                cursor.set_position((string_table_start + offset).into());
                let name = binrw::NullString::read(cursor)?;
                let len = name.len();
                String::from_utf8(name.0)
                    .wrap_err_with(|| format!("invalid symbol long string of len {}", len))?
            }
        };

        eprintln!("sym: {name: <20} {sym:?}");

        cursor.set_position(pos);
    }

    std::fs::write("out.exe", outfile_buf)?;

    Ok(())
}

fn parse_section_header_name(name: [u8; 8]) -> Result<String, Utf8Error> {
    let end = name.iter().position(|&d| d == 0).unwrap_or(7);
    let slice = &name[..end];
    std::str::from_utf8(slice).map(ToOwned::to_owned)
}

fn encode_section_header_name(name: &str) -> [u8; 8] {
    let mut bytes = [0; 8];
    bytes[..name.len()].copy_from_slice(name.as_bytes());
    bytes
}
