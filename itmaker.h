#pragma once
#include "pelib.h"
#include <list>
#include <winnt.h>
#include "stdafx.h"

#define IMPORT_TABLE_EXE	0

class CITMaker
{
private:
	DWORD Get_IT_Size();
	void Initialization(int iType);
protected:
public:
	DWORD dwSize;
	PCHAR pMem;
	CITMaker (int iType);
	~CITMaker();
	void Build(DWORD dwRVA);
};