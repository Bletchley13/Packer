#pragma once
#include "pelib.h"
#include "itmaker.h"
//----------------------------------------------------------------
class CPECryptor: public CPELibrary
{
private:
	//----------------------------------------
	PCHAR pNewSection;
	//----------------------------------------
	DWORD GetFunctionVA(void* FuncName);
	void* ReturnToBytePtr(void* FuncName, DWORD findstr);
	void CopyData1();
	void SetSectionsWritePermission();
	//----------------------------------------
protected:
	//----------------------------------------
	CITMaker *ImportTableMaker;
public:	
	//----------------------------------------
	void CryptFile();
	//----------------------------------------
};
//----------------------------------------------------------------