using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace HellgateLoader.SyscallRes
{
    class SyscallTable
    {
        public static List<APITableEntry> Syscall_list = new List<APITableEntry>();

        public SyscallTable()
        {

            APITableEntry v1 = new APITableEntry();
            APITableEntry v2 = new APITableEntry();
            APITableEntry v3 = new APITableEntry();

            v1.Name = "NtAllocateVirtualMemory";
            v2.Name = "NtCreateThreadEx";
            v3.Name = "NtWaitForSingleObject";

            Syscall_list.Add(v1);
            Syscall_list.Add(v2);
            Syscall_list.Add(v3);

            return;
        }

        public struct APITableEntry
        {
            public string Name;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 24)]
            public byte[] syscall_byte;
        }
    }
}
