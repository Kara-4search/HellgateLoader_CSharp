using HellgateLoader.SyscallRes;
using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using static HellgateLoader.NativeStructs;
using static HellgateLoader.SyscallRes.SyscallTable;
using static HellgateLoader.Utils.MemoryUtil;

namespace HellgateLoader.Utils
{
    class ModuleUtil
    {

        public static IMAGE_SECTION_HEADER[] GetSectionArray(
            MemoryStream ModuleStream,
            IMAGE_FILE_HEADER IMAGE_FILE_HEADER_instance,
            IMAGE_DOS_HEADER IMAGE_DOS_HEADER_instance,
            IMAGE_NT_HEADER64 IMAGE_NT_HEADER64_instance)
        {
            IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER_instance = new IMAGE_SECTION_HEADER();
            IMAGE_SECTION_HEADER[] IMAGE_SECTION_HEADER_array = new IMAGE_SECTION_HEADER[IMAGE_FILE_HEADER_instance.NumberOfSections];

            for (Int16 count = 0; count < IMAGE_FILE_HEADER_instance.NumberOfSections; count++)
            {

                Int64 Section_offset = GetModuleSectionOffset(count, IMAGE_DOS_HEADER_instance, IMAGE_NT_HEADER64_instance);

                IMAGE_SECTION_HEADER_instance = (IMAGE_SECTION_HEADER)GetStructureFromBlob(
                    ModuleStream, Section_offset,
                    Marshal.SizeOf(IMAGE_SECTION_HEADER_instance),
                    IMAGE_SECTION_HEADER_instance);

                IMAGE_SECTION_HEADER_array[count] = IMAGE_SECTION_HEADER_instance;
                Console.WriteLine(IMAGE_SECTION_HEADER_instance.SectionName);
            }

            // Console.WriteLine(IMAGE_FILE_HEADER_instance.NumberOfSections);



            return IMAGE_SECTION_HEADER_array;
        }


        private static Int64 GetModuleSectionOffset(Int16 count, IMAGE_DOS_HEADER IMAGE_DOS_HEADER_instance, IMAGE_NT_HEADER64 IMAGE_NT_HEADER64_instance)
        {
            Int64 Section_offset = IMAGE_DOS_HEADER_instance.e_lfanew
                + Marshal.SizeOf(typeof(IMAGE_FILE_HEADER))
                + IMAGE_NT_HEADER64_instance.FileHeader.SizeOfOptionalHeader
                + sizeof(Int32) // sizeof(DWORD)
                + (Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)) * count);

            return Section_offset;
        }

        public static IMAGE_SECTION_HEADER GetSectionByRVA(Int64 rva, IMAGE_SECTION_HEADER[] IMAGE_SECTION_HEADER_array)
        {
            // this.ModuleSectionHeaders.Where(x => rva > x.VirtualAddress && rva <= x.VirtualAddress + x.SizeOfRawData).First();

            for (int count = 0; count < IMAGE_SECTION_HEADER_array.Count(); count++)
            {
                if (rva > IMAGE_SECTION_HEADER_array[count].VirtualAddress &&
                    rva <= IMAGE_SECTION_HEADER_array[count].VirtualAddress + IMAGE_SECTION_HEADER_array[count].SizeOfRawData)
                {
                    return IMAGE_SECTION_HEADER_array[count];
                }
            }

            IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER_instance = new IMAGE_SECTION_HEADER();
            return IMAGE_SECTION_HEADER_instance;
        }

        public static Int64 ConvertRvaToOffset(Int64 rva, IMAGE_SECTION_HEADER[] IMAGE_SECTION_HEADER_array)
        {
            IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER_instance = GetSectionByRVA(rva, IMAGE_SECTION_HEADER_array);

            Int64 offset = rva - IMAGE_SECTION_HEADER_instance.VirtualAddress + IMAGE_SECTION_HEADER_instance.PointerToRawData;
            return offset;
        }

        public static void SetSyscallTable(string ModulePath)
        {
            MemoryStream ModuleStream = MemoryUtil.LoadModule(ModulePath);
            int IMAGE_DIRECTORY_ENTRY_EXPORT = 0;

            IMAGE_DOS_HEADER IMAGE_DOS_HEADER_instance = new IMAGE_DOS_HEADER();
            IMAGE_DOS_HEADER_instance = (IMAGE_DOS_HEADER)MemoryUtil.GetStructureFromBlob(
                ModuleStream,
                0,
                Marshal.SizeOf(IMAGE_DOS_HEADER_instance),
                IMAGE_DOS_HEADER_instance);

            IMAGE_NT_HEADER64 IMAGE_NT_HEADER64_instance = new IMAGE_NT_HEADER64();
            IMAGE_NT_HEADER64_instance = (IMAGE_NT_HEADER64)MemoryUtil.GetStructureFromBlob(
                ModuleStream,
                IMAGE_DOS_HEADER_instance.e_lfanew,
                Marshal.SizeOf(IMAGE_NT_HEADER64_instance),
                IMAGE_NT_HEADER64_instance);

            IMAGE_FILE_HEADER IMAGE_FILE_HEADER_instance = IMAGE_NT_HEADER64_instance.FileHeader;
            IMAGE_SECTION_HEADER[] IMAGE_SECTION_HEADER_array = new IMAGE_SECTION_HEADER[IMAGE_FILE_HEADER_instance.NumberOfSections];
            IMAGE_SECTION_HEADER_array = GetSectionArray(
                ModuleStream,
                IMAGE_FILE_HEADER_instance,
                IMAGE_DOS_HEADER_instance,
                IMAGE_NT_HEADER64_instance);

            IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY_instance = IMAGE_NT_HEADER64_instance.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            // Console.WriteLine(IMAGE_DATA_DIRECTORY_instance.VirtualAddress);

            IMAGE_EXPORT_DIRECTORY IMAGE_EXPORT_DIRECTORY_instance = new IMAGE_EXPORT_DIRECTORY();
            IMAGE_EXPORT_DIRECTORY_instance = (IMAGE_EXPORT_DIRECTORY)MemoryUtil.GetStructureFromBlob(
                ModuleStream,
                ConvertRvaToOffset(IMAGE_DATA_DIRECTORY_instance.VirtualAddress, IMAGE_SECTION_HEADER_array),
                Marshal.SizeOf(IMAGE_EXPORT_DIRECTORY_instance),
                IMAGE_EXPORT_DIRECTORY_instance);

            SetSyscallBytes(ModuleStream, IMAGE_EXPORT_DIRECTORY_instance, IMAGE_SECTION_HEADER_array);

        }

        private static void SetSyscallBytes(
            MemoryStream ModuleStream,
            IMAGE_EXPORT_DIRECTORY IMAGE_EXPORT_DIRECTORY_instance,
            IMAGE_SECTION_HEADER[] IMAGE_SECTION_HEADER_array)
        {
            Int64 AddressOfFunctions_offset = ConvertRvaToOffset(IMAGE_EXPORT_DIRECTORY_instance.AddressOfFunctions, IMAGE_SECTION_HEADER_array);
            Int64 AddressOfNameOrdinals_offset = ConvertRvaToOffset(IMAGE_EXPORT_DIRECTORY_instance.AddressOfNameOrdinals, IMAGE_SECTION_HEADER_array);
            Int64 AddressOfNames_offset = ConvertRvaToOffset(IMAGE_EXPORT_DIRECTORY_instance.AddressOfNames, IMAGE_SECTION_HEADER_array);

            SyscallTable Syscall_table = new SyscallTable();

            UInt32 NumberOfNames = IMAGE_EXPORT_DIRECTORY_instance.NumberOfNames;

            for (int iterate_num = 0; iterate_num < NumberOfNames; iterate_num++)
            {
                UInt32 AddressOfNames_single_rva = ReadInt32FromStream(ModuleStream, AddressOfNames_offset + iterate_num * 4);
                Int64 AddressOfNames_single_offset = ConvertRvaToOffset(AddressOfNames_single_rva, IMAGE_SECTION_HEADER_array);

                string FuncName_temp = ReadAscStrFromStream(ModuleStream, AddressOfNames_single_offset);
                // Console.WriteLine(Func_name);

                for (int index = 0; index < SyscallTable.Syscall_list.Count(); index++)
                {
                    if (FuncName_temp.ToLower() == SyscallTable.Syscall_list[index].Name.ToLower())
                    {
                        UInt16 AddressOfNamesOrdinals_single_offset = ReadInt16FromStream(
                            ModuleStream,
                            AddressOfNameOrdinals_offset + 2 * iterate_num);

                        Console.WriteLine(AddressOfNamesOrdinals_single_offset);

                        UInt32 AddressOfFunctions_single_rva = ReadInt32FromStream(
                            ModuleStream, AddressOfFunctions_offset + 4 * AddressOfNamesOrdinals_single_offset);

                        Int64 AddressOfFunctions_single_offset = ConvertRvaToOffset(AddressOfFunctions_single_rva, IMAGE_SECTION_HEADER_array);

                        byte[] Syscall_byte = new byte[24];
                        Syscall_byte = ReadSyscallFromStream(ModuleStream, AddressOfFunctions_single_offset);

                        APITableEntry APITableEntry_instance = SyscallTable.Syscall_list[index];
                        APITableEntry_instance.Name = Syscall_list[index].Name;
                        APITableEntry_instance.syscall_byte = Syscall_byte;
                        SyscallTable.Syscall_list[index] = APITableEntry_instance;

                        for (int temp_num = 0; temp_num < Syscall_byte.Length; temp_num++)
                        {
                            Console.Write("{0} ", Syscall_byte[temp_num].ToString("x2"));

                        }
                        Console.Write("\n");
                    }
                }
            }
        }
    }
}
