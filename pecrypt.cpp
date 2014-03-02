/* pecrypt.cpp --

   This file is part of the "PE Maker".

   Copyright (C) 2005-2006 Ashkbiz Danehkar
   All Rights Reserved.

   "PE Maker" library are free software; you can redistribute them
   and/or modify them under the terms of the GNU General Public License as
   published by the Free Software Foundation.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYRIGHT.TXT.
   If not, write to the Free Software Foundation, Inc.,
   59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

   yodap's Forum:
   http://yodap.sourceforge.net/forum/

   yodap's Site:
   http://yodap.has.it
   http://yodap.cjb.net
   http://yodap.sourceforge.net

   Ashkbiz Danehkar
   <ashkbiz@yahoo.com>
*/
#include "stdafx.h"
#include <winnt.h>
#include <imagehlp.h>//#include <Dbghelp.h>
#include "pecrypt.h"
#include "loader.h"

#ifdef _DEBUG
#define DEBUG_NEW
#endif

const char *szWindowsAPIs[]=
{
	"Kernel32.dll",
	"GetModuleHandleA",
	"VirtualProtect",
	"GetModuleFileNameA",
	"CreateFileA",
	"GlobalAlloc",
	0,
	0,
};

//================================================================
//----------------------------------------------------------------
// Function: ReturnToBytePtr
// void* FuncNum:   Function Name
// DWORD findstr:   String to find
//
// This code was written by FEUERRADER [AHTeam], Thanks him!
void* CPECryptor::ReturnToBytePtr(void* FuncName, DWORD findstr)
{
	void* tmpd;
	__asm
	{
		mov eax, FuncName
		jmp df
hjg:	inc eax
df:		mov ebx, [eax]
		cmp ebx, findstr
		jnz hjg
		mov tmpd, eax
	}
	return tmpd;
}
//================================================================
//----------------------------------------------------------------
void CPECryptor::CryptFile()
{
	PCHAR ch_temp;
	DWORD i;
	PIMAGE_SECTION_HEADER pimage_section_header;
	DWORD dwNewSectionSize;
	DWORD dwCodeSize;
	DWORD dwCodeOffset;
	//----------------------------------------
	//callback1(0,0);
	//i=(DWORD)DynLoader;
	ImportTableMaker = new CITMaker(IMPORT_TABLE_EXE);
	ch_temp=(PCHAR)DWORD(ReturnToBytePtr(DynLoader, DYN_LOADER_START_MAGIC))+4;
	dwCodeSize=DWORD(ReturnToBytePtr(DynLoader, DYN_LOADER_END_MAGIC))-DWORD(ch_temp);
	dwCodeOffset = ImportTableMaker->dwSize;
	dwNewSectionSize = dwCodeSize + ImportTableMaker->dwSize;
	pNewSection=new CHAR[dwNewSectionSize];
	memcpy(pNewSection+dwCodeOffset, ch_temp, dwCodeSize);
	printf("NewSection %d\n", pNewSection);
	printf("NewSection+offset %d\n", pNewSection+dwCodeOffset);
	printf("CodeOffset %d\n", dwCodeOffset);
	//----------------------------------------
	CopyData1();

	//----------------------------------------
	pimage_section_header=AddNewSection(".xxx",dwNewSectionSize);
	ImportTableMaker->Build(pimage_section_header->VirtualAddress);// build import table by the current virtual address
	memcpy(pNewSection, ImportTableMaker->pMem, ImportTableMaker->dwSize);
	//----------------------------------------
	memcpy(image_section[image_nt_headers->FileHeader.NumberOfSections-1], 
		   pNewSection, 
		   dwNewSectionSize);
	image_nt_headers->OptionalHeader.AddressOfEntryPoint=pimage_section_header->VirtualAddress + dwCodeOffset;
	image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress=pimage_section_header->VirtualAddress;
	image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size=ImportTableMaker->dwSize;
	SetSectionsWritePermission();
	//----------------------------------------
	_tprintf(_T("Entry Point %x\n"), image_nt_headers->OptionalHeader.AddressOfEntryPoint);
	//callback1(100,0);
	delete []pNewSection;
	delete ImportTableMaker;
}
//----------------------------------------------------------------

typedef struct
{
	DWORD dwReserved1;
	DWORD dwImageBase;
	DWORD dwOrgEntryPoint;
	DWORD dwImportVirtualAddress;
}t_DATA_1, *pt_DATA_1;

void CPECryptor::CopyData1()
{
	int i, API_num;
	PCHAR pData1;
	DWORD dwOffset;
	size_t l;
	UCHAR temp;
	pt_DATA_1 pDataTable=new(t_DATA_1);
	//----------------------------------------
	pDataTable->dwReserved1=0xCCCCCCCC;
	pDataTable->dwImageBase=image_nt_headers->OptionalHeader.ImageBase;
	pDataTable->dwOrgEntryPoint=image_nt_headers->OptionalHeader.AddressOfEntryPoint;
	pDataTable->dwImportVirtualAddress=image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	//----------------------------------------
	printf("dwImageBase %x\n",pDataTable->dwImageBase );
	printf("dwOrgEntryPoint %x\n", pDataTable->dwOrgEntryPoint);
	printf("dwImportVirtualAddress %x\n",pDataTable->dwImportVirtualAddress);
	
	pData1=(PCHAR)ReturnToBytePtr(pNewSection, DYN_LOADER_START_DATA1);
	memcpy(pData1,pDataTable,sizeof(t_DATA_1));
	dwOffset=sizeof(t_DATA_1);
	i=API_num=0;
    temp=0;
	do
	{
		l=strlen(szWindowsAPIs[i])+1;
		memcpy(pData1+dwOffset,szWindowsAPIs[i],l);
		dwOffset+=l;
		do
		{
			i++;
			if(szWindowsAPIs[i]!=0)
			{	
				l=strlen(szWindowsAPIs[i])+1;
				memcpy(pData1+dwOffset,szWindowsAPIs[i],l);
				dwOffset+=l;
				API_num++;
			}
			else
			{
				CopyMemory(pData1+dwOffset,&temp,1);
				dwOffset++;
			}
		}while(szWindowsAPIs[i]!=0);
		i++;
	}
	while(szWindowsAPIs[i]!=0);
	//----------------------------------------
	delete pDataTable;
}
//----------------------------------------------------------------
void CPECryptor::SetSectionsWritePermission()
{
	for(int i=0;i<image_nt_headers->FileHeader.NumberOfSections;i++)
	{
		image_section_header[i]->Characteristics=0xC0000040;
	}
}
//----------------------------------------------------------------