using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace HellgateLoader.Utils
{
    class MemoryUtil
    {
        public static MemoryStream LoadModule(string ModulePath)
        {
            byte[] ModuleBlob = File.ReadAllBytes(ModulePath);
            if (ModuleBlob.Length == 0x00)
            {
                Console.WriteLine("Empty module content: " + ModulePath);
                return null;
            }

            MemoryStream ModuleStream = new MemoryStream(ModuleBlob.ToArray());
            return ModuleStream;
        }

        public static Object GetStructureFromBlob(MemoryStream ModuleStream, Int64 offset, int TypeSize, Object Object_instance)
        {
            byte[] bytes = GetStructureBytesFromOffset(ModuleStream, offset, TypeSize);
            if (Marshal.SizeOf(Object_instance) != bytes.Length)
                return default;

            IntPtr ptr = Marshal.AllocHGlobal(TypeSize);
            Marshal.Copy(bytes.ToArray(), 0, ptr, bytes.Length);
            Object Temp_instance = Marshal.PtrToStructure(ptr, Object_instance.GetType());

            Marshal.FreeHGlobal(ptr);
            return Temp_instance;
        }

        public static byte[] GetStructureBytesFromOffset(MemoryStream ModuleStream, Int64 offset, int TypeSize)
        {
            byte[] s = new byte[TypeSize];
            ModuleStream.Seek(offset, SeekOrigin.Begin);
            ModuleStream.Read(s, 0, TypeSize);
            return s;
        }

        public static UInt16 ReadInt16FromStream(MemoryStream ModuleStream, Int64 offset)
        {
            byte[] s = new byte[2];
            ModuleStream.Seek(offset, SeekOrigin.Begin);
            ModuleStream.Read(s, 0, 2);
            return BitConverter.ToUInt16(s, 0);
        }

        public static UInt32 ReadInt32FromStream(MemoryStream ModuleStream, Int64 offset)
        {
            byte[] s = new byte[4];
            ModuleStream.Seek(offset, SeekOrigin.Begin);
            ModuleStream.Read(s, 0, 4);
            return BitConverter.ToUInt32(s, 0);
        }

        public static byte[] ReadSyscallFromStream(MemoryStream ModuleStream, Int64 offset)
        {
            byte[] s = new byte[24];
            ModuleStream.Seek(offset, SeekOrigin.Begin);
            ModuleStream.Read(s, 0, 24);
            return s;
        }

        public static string ReadAscStrFromStream(MemoryStream ModuleStream, Int64 offset)
        {
            int length = 0;
            ModuleStream.Seek(offset, SeekOrigin.Begin);
            while (ModuleStream.ReadByte() != 0x00)
                length++;

            byte[] s = new byte[length];
            ModuleStream.Seek(offset, SeekOrigin.Begin);
            ModuleStream.Read(s, 0, length);
            return Encoding.ASCII.GetString(s);
        }
    }
}
