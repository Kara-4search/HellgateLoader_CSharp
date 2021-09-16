using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
            public byte[] syscall_byte;
        }
    }
}
