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
					// ��ȡ�����ܵ�Դ�ļ�
					char szSrcFileName[MAX_PATH] = {0};
					HWND hEditSrc = GetDlgItem(hDlg, IDC_EDIT_SRC);
					GetWindowText(hEditSrc, szSrcFileName, MAX_PATH);
					if (strcmp(szSrcFileName,"") == 0)
					{
						MessageBox(hDlg, "���ļ�ʧ��", "", 0);
						break;
					}
					LPVOID pSrcBuffer = NULL;
					DWORD dwSrcFileSize = FileToMemory(szSrcFileName, &pSrcBuffer);
					if (0 == dwSrcFileSize)
					{
						MessageBox(hDlg, "���ļ�ʧ��", "", 0);
						break;
					}
					// ����EXE�ļ�
					// ��ȡ��Դ����shell����
					HRSRC hRsrcShell = FindResource(NULL, MAKEINTRESOURCE(IDR_BINARY_SHELL), "binary");
					if (NULL == hRsrcShell)
					{
						MessageBox(hDlg, "��ȡ��Դ�ļ�ʧ��", "", 0);
						break;
					}					
					DWORD dwShellSize = SizeofResource(NULL, hRsrcShell); // ���ļ���С
					if (0 == dwShellSize)
					{
						MessageBox(hDlg, "��Դ��С����", "", 0);
						break;
					}
					HGLOBAL hGlobal = LoadResource(NULL, hRsrcShell);
					if (NULL == hGlobal)
					{
						MessageBox(0,"������Դʧ��", 0,0);
						return FALSE;
					}
					// ��ȡ��Դ����ָ��
					LPVOID pShellBuffer = LockResource(hGlobal);
					if (NULL == pShellBuffer)
					{
						MessageBox(0,"��ȡ��Դָ��ʧ��", 0,0);
						return FALSE;
					}
					// �����ܺ��Դ����׷�ӵ�������
					// ������һ��ʼ����ΪԴ�ļ���С��ǣ���ʮ�������ַ�������$����
					char szSizeFlag[100] = {0};
					sprintf(szSizeFlag, "%d$", dwShellSize);
					LPVOID pNewShellBuffer = NULL;					
					DWORD dwNewShellSize = WriteEncryptedDataToNewSection(pShellBuffer, dwShellSize, &pNewShellBuffer, pSrcBuffer, dwSrcFileSize);
					
					if (0 == dwNewShellSize)
					{
						MessageBox(0,"����ʧ��-AddDataToNewSection", 0,0);
						break;
					}
					// д�뵽���̵�ǰĿ¼��
					char szOutput[MAX_PATH] = {0};
					GetCurrentDirectory(MAX_PATH, szOutput);
					strcat(szOutput, "\\enc_"); // ��ǰĿ¼ + enc_Դ�ļ���
					strcat(szOutput, strrchr(szSrcFileName,'\\') + 1); // ��ǰĿ¼ + enc_Դ�ļ���					
					//MessageBox(hDlg, szOutput, 0, 0);
					MemoryToFile(pNewShellBuffer, dwNewShellSize, szOutput);
					free(pSrcBuffer);
					free(pNewShellBuffer);
					MessageBox(hDlg, "�ӿǳɹ�", 0, 0);
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



