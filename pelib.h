#pragma once
#define MAX_SECTION_NUM         20
//----------------------------------------------------------------
class CPELibrary 
{
private:
	//-----------------------------------------
	PCHAR					pMem;
	DWORD					dwFileSize;
	//-----------------------------------------
protected:
	//-----------------------------------------
	PIMAGE_DOS_HEADER		image_dos_header;
	PCHAR					pDosStub;
	DWORD					dwDosStubSize, dwDosStubOffset;
	PIMAGE_NT_HEADERS		image_nt_headers;
	PIMAGE_SECTION_HEADER	image_section_header[MAX_SECTION_NUM];
	PCHAR					image_section[MAX_SECTION_NUM];
	//-----------------------------------------
protected:
	//-----------------------------------------
	DWORD PEAlign(DWORD dwTarNum,DWORD dwAlignTo);
	void AlignmentSections();
	//-----------------------------------------
	DWORD Offset2RVA(DWORD dwRO);
	DWORD RVA2Offset(DWORD dwRVA);
	//-----------------------------------------
	PIMAGE_SECTION_HEADER ImageRVA2Section(DWORD dwRVA);
	PIMAGE_SECTION_HEADER ImageOffset2Section(DWORD dwRO);
	//-----------------------------------------
	DWORD ImageOffset2SectionNum(DWORD dwRVA);
	PIMAGE_SECTION_HEADER AddNewSection(char* szName,DWORD dwSize);
	//-----------------------------------------
public:
	//-----------------------------------------
	CPELibrary();
	~CPELibrary();
	//-----------------------------------------
	void OpenFile(_TCHAR* FileName);
	void SaveFile(_TCHAR* FileName);	
	//-----------------------------------------
};
//----------------------------------------------------------------