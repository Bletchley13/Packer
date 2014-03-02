/* loader.cpp --

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
#include "loader.h"

#ifdef _DEBUG
#define DEBUG_NEW
#endif

void __stdcall DynLoader();
//---------------------------------------------------------
// Thanks FEUERRADER [AHTeam] for idea about using _emit 0! 
//---------------------------------------------------------
// byte ptr		(1 bytes)
#define byte_type(x)			__asm _emit x 
// word ptr		(2 bytes)
#define word_type(x)			byte_type((x>>(0*8))&0xFF)	byte_type((x>>(1*8))&0xFF)
// dword ptr	(4 bytes)
#define dword_type(x)			byte_type((x>>(0*8))&0xFF)	byte_type((x>>(1*8))&0xFF)	byte_type((x>>(2*8))&0xFF)	byte_type((x>>(3*8))&0xFF)
// dword64 ptr	(8 bytes)
#define dword64_type(x)			dword_type(x)	dword_type(x)
// dword64 ptr	(16 bytes)
#define dword128_type(x)		dword64_type(x)	dword64_type(x)
//---------------------------------------------------------
#define bb(x)					__asm _emit x 
#define db						byte_type(0xCC)
#define __random_code1__		dword64_type(0X90909090) // Reserve for random code generation
#define __jmp_api				byte_type(0xFF)	byte_type(0x25)


//----------------------------------------------------------------
void __stdcall DynLoader()
{
_asm
{
//----------------------------------
	dword_type(DYN_LOADER_START_MAGIC)
//----------------------------------
_main_0:
	pushad	// Save the registers context in stack
	call _main_1
_main_1:	
	pop ebp
	sub ebp,offset _main_1 // Get Base EBP
	//====================================================
	mov eax,[ebp+_p_dwImageBase]
	add eax,[eax+03Ch]
	add eax,080h
	mov ecx,[eax]	// image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
	add ecx,[ebp+_p_dwImageBase]
	add ecx,010h	// image_import_descriptor.FirstThunk
	mov eax,[ecx]
	add eax,[ebp+_p_dwImageBase]
	mov ebx,[eax]
	mov [ebp+_p_LoadLibrary],ebx
	add eax,04h
	mov ebx,[eax]
	mov [ebp+_p_GetProcAddress],ebx
	//----------------------------------------------------
	//====================================================
	//------- load library and build api call-jmp --------
	lea edi,[ebp+_p_szKernel32]
	lea ebx,[ebp+_p_GetModuleHandle]
	lea ecx,[ebp+_jmp_GetModuleHandle]
	add ecx,02h
_api_get_lib_address_loop:
		push ecx
		//-------------------
		push edi
		mov eax,offset _p_LoadLibrary
		call [ebp+eax]//LoadLibrary(lpLibFileName);
		//-------------------
		pop ecx
		mov esi,eax	// esi -> hModule
		push edi
		call __strlen
		add esp,04h
		add edi,eax
_api_get_proc_address_loop:
			push ecx
			//-------------------
			push edi
			push esi
			mov eax,offset _p_GetProcAddress
			call [ebp+eax]//GetModuleHandle=GetProcAddress(hModule, lpProcName);
			//--------------------
			pop ecx
			mov [ebx],eax
			mov [ecx],ebx
			add ebx,04h
			add ecx,06h
			push edi
			call __strlen
			add esp,04h
			add edi,eax
			mov al,byte ptr [edi]
		test al,al
		jnz _api_get_proc_address_loop
		inc edi
		mov al,byte ptr [edi]
	test al,al
	jnz _api_get_lib_address_loop
	//----------------------------------------------------
	//====================================================

	// Place your code here ...

	mov eax, 0x401000
	mov ecx, 0x3000
_unpack:
	dec ecx
	mov ebx, [eax+ecx]
	xor ebx, 0xff
	mov [eax+ecx], ebx
	cmp ecx, 0
	jnz _unpack

	//mov [eax], 0x90


	//----------------------------------------------------
	//====================================================
	//----------- get write access for headers -----------
	mov edi,[ebp+_p_dwImageBase]
	add edi,[edi+03Ch]// edi -> IMAGE_NT_HEADERS
	// get write permission by VirtualProtect()
	lea eax,[ebp+_p_ptempbuffer]
	push eax
	push PAGE_READWRITE
	push [edi+0x54]//IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders
	push [ebp+_p_dwImageBase]
	call _jmp_VirtualProtect
	//VirtualProtect(dwImageBase,image_nt_header.OptionalHeader.SizeOfHeaders,PAGE_READWRITE,ptempbuffer);
	//----------------------------------------------------
	//====================================================
	//------------- fix up the import table --------------
	// I have stolen this IT fix-up code from Morphine 2.7 !!
	// so Thanks Holy_Father && Ratter/29A for it. (www.hxdef.org)
	mov ebx,[ebp+_p_dwImportVirtualAddress]
	test ebx,ebx
	jz _DynLoader_export_fixup
	mov esi,[ebp+_p_dwImageBase]
	add ebx,esi									//dwImageBase + dwImportVirtualAddress
_it_fixup_get_lib_address_loop:
		mov eax,[ebx+00Ch]						//image_import_descriptor.Name
		test eax,eax
		jz _DynLoader_export_fixup
		
		mov ecx,[ebx+010h]						//image_import_descriptor.FirstThunk
		add ecx,esi
		mov [ebp+_p_dwThunk],ecx				//dwThunk
		mov ecx,[ebx]							//image_import_descriptor.Characteristics
		test ecx,ecx
		jnz _it_fixup_table
			mov ecx,[ebx+010h]
_it_fixup_table:
		add ecx,esi
		mov [ebp+_p_dwHintName],ecx				//dwHintName
		add eax,esi								//image_import_descriptor.Name + dwImageBase = ModuleName
		push eax								//lpLibFileName
		mov eax,offset _p_LoadLibrary
		call [ebp+eax]							//LoadLibrary(lpLibFileName);

		test eax,eax
		jz _DynLoader_end
		mov edi,eax
_it_fixup_get_proc_address_loop:
			mov ecx,[ebp+_p_dwHintName]			//dwHintName
			mov edx,[ecx]						//image_thunk_data.Ordinal
			test edx,edx
			jz _it_fixup_next_module
			test edx,080000000h					//.IF( import by ordinal )
			jz _it_fixup_by_name
				and edx,07FFFFFFFh				//get ordinal
				jmp _it_fixup_get_addr
_it_fixup_by_name:
			add edx,esi							//image_thunk_data.Ordinal + dwImageBase = OrdinalName
			inc edx
			inc edx								//OrdinalName.Name
_it_fixup_get_addr:
			push edx							//lpProcName
			push edi							//hModule						
			mov eax,offset _p_GetProcAddress
			call [ebp+eax]						//GetProcAddress(hModule, lpProcName);

			mov ecx,[ebp+_p_dwThunk]			//dwThunk
			mov [ecx],eax
			add dword ptr [ebp+_p_dwThunk],004h	//dwThunk => next dwThunk
			add dword ptr [ebp+_p_dwHintName],004h//dwHintName => next dwHintName
		jmp _it_fixup_get_proc_address_loop
_it_fixup_next_module:
		add ebx,014h							//sizeof(IMAGE_IMPORT_DESCRIPTOR)
	jmp _it_fixup_get_lib_address_loop
	
_DynLoader_export_fixup:
_DynLoader_end:
	//----------------------------------------------------
	//====================================================
	//--------- Prepare the SEH for OEP approach ---------
	mov eax,[ebp+_p_dwImageBase]
	add eax,[ebp+_p_dwOrgEntryPoint]
	mov [esp+10h],eax	// pStack.Ebx <- EAX
	lea eax,[ebp+_except_handler1_OEP_Jump]
	mov [esp+1Ch],eax	// pStack.Eax <- EAX
	popad	// Restore the first registers context from stack
	//----------------------------------------------------
  	// the structured exception handler (SEH) installation 
	push eax
	xor  eax, eax
	push dword ptr fs:[0]		// NT_TIB32.ExceptionList
	mov fs:[0],esp	// NT_TIB32.ExceptionList <-ESP
	dword_type(0xCCCCCCCC)// Raise a INT 3 Exception
	//----------------------------------------------------
	//====================================================
//--------------------------------------------------------
//========================================================
//------------- t_size strlen(LPCTSTR lpStr) ----------------
__strlen:
	push ebp
	mov ebp,esp
	push ecx
	push esi
	push ebx
	mov esi,[ebp+08h]// -> Destination
	mov ecx,255// -> Length
	xor ebx,ebx
_strlenloop:
		lods byte ptr ds:[esi]
		cmp al,00h
		jz _endbufstrlen
		inc ebx
	loop _strlenloop
_endbufstrlen:
	mov eax,ebx
	inc eax
	pop ebx
	pop esi
	pop ecx
	mov esp,ebp
	pop ebp
	ret
//--------------------------------------------------------
//========================================================
// -------- exception handler expression filter ----------
_except_handler1_OEP_Jump:
	push ebp
	mov ebp,esp
	mov eax,[ebp+010h]	// PCONTEXT: pContext <- EAX
	//---------------
	push edi
	// restore original SEH
	mov edi,[eax+0C4h]	// pContext.Esp
	push dword ptr ds:[edi]
	pop dword ptr fs:[0]
	add dword ptr [eax+0C4h],8	// pContext.Esp
	
	// set the Eip to the OEP
	mov edi,[eax+0A4h] // EAX <- pContext.Ebx
	mov [eax+0B8h],edi // pContext.Eip <- EAX
	// 
	pop edi
	//---------------
	mov eax, EXCEPTION_CONTINUE_SEARCH
	leave
	ret
//--------------------------------------------------------
//========================================================
	dword_type(DYN_LOADER_START_DATA1)
//----------------------------------
_p_dwImageBase:					dword_type(0xCCCCCCCC)
_p_dwOrgEntryPoint:				dword_type(0xCCCCCCCC)
_p_dwImportVirtualAddress:		dword_type(0xCCCCCCCC)
//----------------------------------
_p_szKernel32:				//db "Kernel32.dll",0,13
		db db db db db db db db db db db db db
_p_szGetModuleHandle:		//db "GetModuleHandleA",0,17
		db db db db db db db db db db db db db db db db db
_p_szVirtualProtect:		//db "VirtualProtect",0,15
		db db db db db db db db db db db db db db db
_p_szGetModuleFileName:	//db "GetModuleFileNameA",0,19
		db db db db	db db db db	db db db db db db db db db db db
_p_szCreateFile:			//db "CreateFileA",0,12
		db db db db db db db db db db db db
_p_szGlobalAlloc:			//db "GlobalAlloc",0,12
		db db db db db db db db db db db db
		byte_type(0)
		byte_type(0)
//----------------------------------
_p_LoadLibrary:					dword_type(0xCCCCCCCC)
_p_GetProcAddress:				dword_type(0xCCCCCCCC)
_p_GetModuleHandle:			
								dword_type(0xCCCCCCCC)
								dword_type(0xCCCCCCCC)
								dword_type(0xCCCCCCCC)
								dword_type(0xCCCCCCCC)
								dword_type(0xCCCCCCCC)

_jmp_GetModuleHandle:			__jmp_api	dword_type(0xCCCCCCCC)
_jmp_VirtualProtect:			__jmp_api	dword_type(0xCCCCCCCC)
_jmp_GetModuleFileName:			__jmp_api	dword_type(0xCCCCCCCC)
_jmp_CreateFile:				__jmp_api	dword_type(0xCCCCCCCC)
_jmp_GlobalAlloc:				__jmp_api	dword_type(0xCCCCCCCC)
_p_dwThunk:						dword_type(0xCCCCCCCC)
_p_dwHintName:					dword_type(0xCCCCCCCC)
_p_ptempbuffer:					dword_type(0xCCCCCCCC)
//----------------------------------
	dword_type(DYN_LOADER_END_MAGIC)
//----------------------------------
}
}
//----------------------------------------------------------------