using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace HellgateLoader.SyscallRes
{
    class SyscallDelegates
    {
		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate uint NtAllocateVirtualMemory(
			IntPtr ProcessHandle,
			ref IntPtr BaseAddress,
			IntPtr ZeroBits,
			ref IntPtr RegionSize,
			ulong AllocationType,
			ulong Protect);

		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate uint NtCreateThreadEx(
			out IntPtr hThread,
			uint DesiredAccess,
			IntPtr ObjectAttributes,
			IntPtr ProcessHandle,
			IntPtr lpStartAddress,
			IntPtr lpParameter,
			bool CreateSuspended,
			uint StackZeroBits,
			uint SizeOfStackCommit,
			uint SizeOfStackReserve,
			IntPtr lpBytesBuffer);

		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate uint NtWaitForSingleObject(IntPtr Object, bool Alertable, uint Timeout);
	}
}
