// EncryptMain.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "PE.hpp"

BOOL CALLBACK MainDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{ 	
	DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, MainDialogProc);

	

	
	return 0;
}

BOOL CALLBACK MainDialogProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG: 
		{		
			HWND hwndOwner = NULL;
			RECT rcOwner, rcDlg, rc;			
			// Get the owner window and dialog box rectangles. 			
			if ((hwndOwner = GetParent(hDlg)) == NULL) 
			{
				hwndOwner = GetDesktopWindow(); 
			}			
			GetWindowRect(hwndOwner, &rcOwner); 
			GetWindowRect(hDlg, &rcDlg); 
			CopyRect(&rc, &rcOwner); 
			
			// Offset the owner and dialog box rectangles so that right and bottom 
			// values represent the width and height, and then offset the owner again 
			// to discard space taken up by the dialog box. 
			
			OffsetRect(&rcDlg, -rcDlg.left, -rcDlg.top); 
			OffsetRect(&rc, -rc.left, -rc.top); 
			OffsetRect(&rc, -rcDlg.right, -rcDlg.bottom); 
			
			// The new position is the sum of half the remaining space and the owner's 
			// original position. 
			
			SetWindowPos(hDlg, 
				HWND_TOP, 
				rcOwner.left + (rc.right / 2), 
				rcOwner.top + (rc.bottom / 2), 
				0, 0,          // Ignores size arguments. 
				SWP_NOSIZE); 
			
			return TRUE;
		}
	case WM_COMMAND:
		{
			switch (LOWORD(wParam))
			{
			case IDC_BUTTON_OPEN:
				{					
					char szFileName[MAX_PATH] = {0};
					LPCSTR szPeFileExt = "EXE\0*.EXE\0";
					OPENFILENAME openFileName = {0};
					openFileName.lStructSize = sizeof(OPENFILENAME);
					openFileName.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
					openFileName.hwndOwner = hDlg;
					openFileName.lpstrFilter = szPeFileExt;
					openFileName.lpstrFile = szFileName;
					openFileName.nMaxFile = MAX_PATH;
					GetOpenFileName(&openFileName);
					HWND hEditSrc = GetDlgItem(hDlg, IDC_EDIT_SRC);
					SetWindowText(hEditSrc, openFileName.lpstrFile);
					
					return TRUE;
				}
			case IDC_BUTTON_ENCRYPT:
				{
					// 读取待加密的源文件
					char szSrcFileName[MAX_PATH] = {0};
					HWND hEditSrc = GetDlgItem(hDlg, IDC_EDIT_SRC);
					GetWindowText(hEditSrc, szSrcFileName, MAX_PATH);
					if (strcmp(szSrcFileName,"") == 0)
					{
						MessageBox(hDlg, "打开文件失败", "", 0);
						break;
					}
					LPVOID pSrcBuffer = NULL;
					DWORD dwSrcFileSize = FileToMemory(szSrcFileName, &pSrcBuffer);
					if (0 == dwSrcFileSize)
					{
						MessageBox(hDlg, "打开文件失败", "", 0);
						break;
					}
					// 加密EXE文件
					// 读取资源区的shell程序
					HRSRC hRsrcShell = FindResource(NULL, MAKEINTRESOURCE(IDR_BINARY_SHELL), "binary");
					if (NULL == hRsrcShell)
					{
						MessageBox(hDlg, "读取壳源文件失败", "", 0);
						break;
					}					
					DWORD dwShellSize = SizeofResource(NULL, hRsrcShell); // 壳文件大小
					if (0 == dwShellSize)
					{
						MessageBox(hDlg, "资源大小错误", "", 0);
						break;
					}
					HGLOBAL hGlobal = LoadResource(NULL, hRsrcShell);
					if (NULL == hGlobal)
					{
						MessageBox(0,"加载资源失败", 0,0);
						return FALSE;
					}
					// 获取资源数据指针
					LPVOID pShellBuffer = LockResource(hGlobal);
					if (NULL == pShellBuffer)
					{
						MessageBox(0,"获取资源指针失败", 0,0);
						return FALSE;
					}
					// 将加密后的源程序追加到新增节
					// 新增节一开始定义为源文件大小标记，是十进制数字符串，以$结束
					char szSizeFlag[100] = {0};
					sprintf(szSizeFlag, "%d$", dwShellSize);
					LPVOID pNewShellBuffer = NULL;					
					DWORD dwNewShellSize = WriteEncryptedDataToNewSection(pShellBuffer, dwShellSize, &pNewShellBuffer, pSrcBuffer, dwSrcFileSize);
					
					if (0 == dwNewShellSize)
					{
						MessageBox(0,"加密失败-AddDataToNewSection", 0,0);
						break;
					}
					// 写入到磁盘当前目录下
					char szOutput[MAX_PATH] = {0};
					GetCurrentDirectory(MAX_PATH, szOutput);
					strcat(szOutput, "\\enc_"); // 当前目录 + enc_源文件名
					strcat(szOutput, strrchr(szSrcFileName,'\\') + 1); // 当前目录 + enc_源文件名					
					//MessageBox(hDlg, szOutput, 0, 0);
					MemoryToFile(pNewShellBuffer, dwNewShellSize, szOutput);
					free(pSrcBuffer);
					free(pNewShellBuffer);
					MessageBox(hDlg, "加壳成功", 0, 0);
					return TRUE;
				}
			}
			return TRUE;
		}
	case WM_CLOSE:
		{
			EndDialog(hDlg, 0);
			return TRUE;
		}
	}
	return FALSE;
}



