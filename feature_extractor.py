import pefile
import datetime


def extract_features(file_path):

    pe = pefile.PE(file_path)

    feature_vector = {

        "e_magic": pe.DOS_HEADER.e_magic,
        "e_cblp": pe.DOS_HEADER.e_cblp,
        "e_cp": pe.DOS_HEADER.e_cp,
        "e_crlc": pe.DOS_HEADER.e_crlc,
        "e_cparhdr": pe.DOS_HEADER.e_cparhdr,
        "e_minalloc": pe.DOS_HEADER.e_minalloc,
        "e_maxalloc": pe.DOS_HEADER.e_maxalloc,
        "e_ss": pe.DOS_HEADER.e_ss,
        "e_sp": pe.DOS_HEADER.e_sp,
        "e_csum": pe.DOS_HEADER.e_csum,
        "e_ip": pe.DOS_HEADER.e_ip,
        "e_cs": pe.DOS_HEADER.e_cs,
        "e_lfarlc": pe.DOS_HEADER.e_lfarlc,
        "e_ovno": pe.DOS_HEADER.e_ovno,

        "e_res": sum(pe.DOS_HEADER.e_res),
        "e_oemid": pe.DOS_HEADER.e_oemid,
        "e_oeminfo": pe.DOS_HEADER.e_oeminfo,
        "e_res2": sum(pe.DOS_HEADER.e_res2),

        "e_lfanew": pe.DOS_HEADER.e_lfanew,

        "Machine": pe.FILE_HEADER.Machine,
        "NumberOfSections": pe.FILE_HEADER.NumberOfSections,

        "CreationYear":
            datetime.datetime.utcfromtimestamp(
                pe.FILE_HEADER.TimeDateStamp
            ).year,

        "PointerToSymbolTable":
            pe.FILE_HEADER.PointerToSymbolTable,

        "NumberOfSymbols":
            pe.FILE_HEADER.NumberOfSymbols,

        "SizeOfOptionalHeader":
            pe.FILE_HEADER.SizeOfOptionalHeader,

        "Characteristics":
            pe.FILE_HEADER.Characteristics,

        "Magic":
            pe.OPTIONAL_HEADER.Magic,

        "MajorLinkerVersion":
            pe.OPTIONAL_HEADER.MajorLinkerVersion,

        "MinorLinkerVersion":
            pe.OPTIONAL_HEADER.MinorLinkerVersion,

        "SizeOfCode":
            pe.OPTIONAL_HEADER.SizeOfCode,

        "SizeOfInitializedData":
            pe.OPTIONAL_HEADER.SizeOfInitializedData,

        "SizeOfUninitializedData":
            pe.OPTIONAL_HEADER.SizeOfUninitializedData,

        "AddressOfEntryPoint":
            pe.OPTIONAL_HEADER.AddressOfEntryPoint,

        "BaseOfCode":
            pe.OPTIONAL_HEADER.BaseOfCode,

        "BaseOfData":
            getattr(
                pe.OPTIONAL_HEADER,
                "BaseOfData",
                0
            ),

        "ImageBase":
            pe.OPTIONAL_HEADER.ImageBase,

        "SectionAlignment":
            pe.OPTIONAL_HEADER.SectionAlignment,

        "FileAlignment":
            pe.OPTIONAL_HEADER.FileAlignment,

        "MajorOperatingSystemVersion":
            pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,

        "MinorOperatingSystemVersion":
            pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,

        "MajorImageVersion":
            pe.OPTIONAL_HEADER.MajorImageVersion,

        "MinorImageVersion":
            pe.OPTIONAL_HEADER.MinorImageVersion,

        "MajorSubsystemVersion":
            pe.OPTIONAL_HEADER.MajorSubsystemVersion,

        "MinorSubsystemVersion":
            pe.OPTIONAL_HEADER.MinorSubsystemVersion,

        "SizeOfImage":
            pe.OPTIONAL_HEADER.SizeOfImage,

        "SizeOfHeaders":
            pe.OPTIONAL_HEADER.SizeOfHeaders,

        "CheckSum":
            pe.OPTIONAL_HEADER.CheckSum,

        "Subsystem":
            pe.OPTIONAL_HEADER.Subsystem,

        "DllCharacteristics":
            pe.OPTIONAL_HEADER.DllCharacteristics,

        "SizeOfStackReserve":
            pe.OPTIONAL_HEADER.SizeOfStackReserve,

        "SizeOfStackCommit":
            pe.OPTIONAL_HEADER.SizeOfStackCommit,

        "SizeOfHeapReserve":
            pe.OPTIONAL_HEADER.SizeOfHeapReserve,

        "SizeOfHeapCommit":
            pe.OPTIONAL_HEADER.SizeOfHeapCommit,

        "LoaderFlags":
            pe.OPTIONAL_HEADER.LoaderFlags,

        "NumberOfRvaAndSizes":
            pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
    }

    print("\nTOTAL FEATURES:")
    print(len(feature_vector))
    # ==========================
    # FILE HEADER FLAGS
    # ==========================

    characteristics = pe.FILE_HEADER.Characteristics

    for i in range(15):

        feature_vector[f"FH_char{i}"] = (
            characteristics >> i
        ) & 1

    # ==========================
    # DLL CHARACTERISTICS
    # ==========================

    dll_char = pe.OPTIONAL_HEADER.DllCharacteristics

    for i in range(11):

        feature_vector[f"OH_DLLchar{i}"] = (
            dll_char >> i
        ) & 1

    return feature_vector

