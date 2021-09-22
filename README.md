# HellgateLoader_CSharp

Blog link: working on it

- Base on the original Hellgate project down below:
	1. https://github.com/am0nsec/SharpHellsGate
	2. https://github.com/am0nsec/HellsGate
- And my other project down below:
	1. [SysCall_ShellcodeLoader](https://github.com/Kara-4search/SysCall_ShellcodeLoad_Csharp)
	2. [HookDetection](https://github.com/Kara-4search/HookDetection_CSharp)
	3. [DInvoke_ShellcodeLoader](https://github.com/Kara-4search/DInvoke_shellcodeload_CSharp)
	4. [NewNtdllBypassInlineHook](https://github.com/Kara-4search/NewNtdllBypassInlineHook_CSharp)

- **I make this project for learning purpose, use it at you own risk.**
- Only tested it on Win10/x64 works fine.
- For better understanding, you really need to read the PDF(https://vxug.fakedoma.in/papers/VXUG/Exclusive/HellsGate.pdf) from the original author.
- Thanks to them I do learn a lot, during code this project.
- Also, there is a little different here, Instead of read the syscall id from the memory, I read 24 bytes as the syscall，
	so you don‘t need to concat them again. I think that would be more convenient for me.
- (From the PDF)This general usage code base self-resolves syscalls without the need for static elements. Additionally, this general usage code base makes zero function invocations to aggregate the syscalls themselves.
- About how it works:
	1. Read the ntdll.dll via IO.stream from disk as MemoryStream.
	2. Find the RVA of function address.
	3. Convert the rva to file offset(RVA - IMAGE_SECTION_HEADER_instance.VirtualAddress + IMAGE_SECTION_HEADER_instance.PointerToRawData;).
	4. Use the offset to find to function offset in MemoryStream.
	5. Read 24 bytes as syscall from MemoryStream with the right offset.
	6. Execute the syscall via delegate.
- The picture down below helps you to understand file offset.
	![avatar](https://github.com/Kara-4search/ProjectPics/blob/main/HellGateLoader_ConvertRVAtoFO.jpg)
- The code from the original project is elegant as hell, guess that is why is called HELLGATE :) :) ~
- You could even modify the code to like injection or something else.

## Usage
1. Set the APIs name that you need in "SyscallTable.cs" ,In this case is:
	        * v1.Name = "NtAllocateVirtualMemory";
            * v2.Name = "NtCreateThreadEx";
            * v3.Name = "NtWaitForSingleObject";
	![avatar](https://raw.githubusercontent.com/Kara-4search/ProjectPics/main/HellGateLoader_APIs.png)

2. Set the shellcode in Program.cs, the default shellcode is a Calc.
	![avatar](https://raw.githubusercontent.com/Kara-4search/ProjectPics/main/HellGateLoader_shellcode.png)

	
## TO-DO list
- Works on both x64/x86
- Restructure the code

## Update history
- NONE

## Reference link:
	1. https://github.com/am0nsec/HellsGate
	2. https://github.com/am0nsec/SharpHellsGate
	3. https://vxug.fakedoma.in/papers/VXUG/Exclusive/HellsGate.pdf 
	4. https://docs.microsoft.com/zh-cn/dotnet/api/system.reflection.bindingflags?view=net-5.0
	5. https://docs.microsoft.com/zh-cn/dotnet/api/system.runtime.compilerservices.runtimehelpers.preparemethod?view=net-5.0
	6. https://docs.microsoft.com/zh-cn/dotnet/api/system.runtime.compilerservices.runtimehelpers.preparemethod?redirectedfrom=MSDN&view=net-5.0#System_Runtime_CompilerServices_RuntimeHelpers_PrepareMethod_System_RuntimeMethodHandle_System_RuntimeTypeHandle___
	7. https://docs.microsoft.com/zh-cn/dotnet/api/system.runtime.interopservices.marshal.allochglobal?view=net-5.0
	8. https://www.cnblogs.com/qintangtao/archive/2013/01/11/2857180.html
	9. https://blog.csdn.net/StriveScript/article/details/6279488
	10. https://www.cnblogs.com/wyping/p/3643243.html
	11. https://blog.csdn.net/e295166319/article/details/52702461
	12. https://blog.csdn.net/qiqi5045/article/details/7736576
	13. https://blog.csdn.net/tianxiayijia1998/article/details/50119435
	14. https://www.runoob.com/csharp/csharp-generic.html
	15. https://www.csharpcodi.com/csharp-examples/System.RuntimeMethodHandle.GetFunctionPointer()/
	16. https://cloud.tencent.com/developer/article/1015264
	17. https://a1ex.online/2020/07/26/PE-to-LoadLibrary-md/
	18. https://www.displayfusion.com/Discussions/View/converting-c-data-types-to-c/?ID=38db6001-45e5-41a3-ab39-8004450204b3