#include <WinSock2.h>
#include <WS2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "Ws2_32.lib")

#define SLEEP_TIME 5000
#define DEFAULT_IP "192.168.43.251"
#define DEFAULT_PORT 55555
#define DEFAULT_BUF_SIZE 1024*1024
#define SERVER_ROOT_DIRECTORY "./ServerRoot"
#define FILE_NOT_FOUND "HTTP/1.1 404 Not Found\r\n\r\n"
#define BAD_REQUEST "HTTP/1.1 400 Bad Request\r\n\r\n"
#define NO_CONTENT "HTTP/1.1 204 No Content\r\n\r\n"
#define NOT_IMPLEMENTED "HTTP/1.1 501 Not Implemented\r\n\r\n"
#define OK "HTTP/1.1 200 OK\r\n\r\n"
#define ACCESS_DENIED "HTTP/1.1 403 Forbidden\r\n\r\n"
#define METHOD_NOT_ALLOWED "HTTP/1.1 405 Method Not Allowed\r\n\r\n"
#define CREATED "HTTP/1.1 201 Created\r\n\r\n"

#define LIST_BEGIN "{\r\n\t\"List\": [\r\n"
#define LIST_END "\r\n\t]\r\n}"

typedef struct HTTPHeader
{
	char *StartingLine;
	char **Headers;
	int HeadersCount;
	char *Method;
	char *Version;
	char *URI;
	int ContentLength;
	char *Content;
} HTTPHeader;

char *Realpath(char *Root, char *Path)
{
	char *Result = (char *)calloc(1, strlen(Root) + strlen(Path) + 1);
	strcpy(Result, Root);
	strcat(Result, Path);
	return Result;
}

int IndexOf(char *Str, int Position, char Symbol)
{
	for (int i=Position; i<strlen(Str); i++)
	{
		if (Str[i] == Symbol)
		{
			return i;
		}
	}
	return -1;
}

int FindInString(char *FindIn, char *FindValue)
{
	int Index = 0, Len = strlen(FindIn);
	if (strlen(FindIn) >= strlen(FindValue))
	{
		char *CmpStr = (char *)calloc(1, strlen(FindValue)+1);
		do
		{
				memcpy(CmpStr, FindIn++, strlen(FindValue));
				Index++;
		}
		while (strcmp(CmpStr, FindValue) && strlen(FindIn) >= strlen(FindValue));
		free(CmpStr);
		return Index <= Len ? Index-1 : -1;
	}
	else
	{
		return -1;
	}
}

char *FindInHeadersList(HTTPHeader *Pack, char *FindValue)
{
	int i, Index;
	char *CurrentStr, *Result;
	if (Pack->HeadersCount > 0)
	{
		for (i = 0; i < Pack->HeadersCount; i++)
		{
			Index = FindInString(*(Pack->Headers + i), ":");
			CurrentStr = (char *)calloc(1, Index + 1);
			memcpy(CurrentStr, *(Pack->Headers + i), Index);
			if (!strcmp(CurrentStr, FindValue))
			{
				Result = (char *)calloc(1, strlen(*(Pack->Headers + i)) - Index - 1);
				memcpy(Result, *(Pack->Headers + i) + Index + 2, strlen(*(Pack->Headers + i)) - Index - 2);
				free(CurrentStr);
				return Result;
			}
		}
		free(CurrentStr);
	}
	return NULL;
}

HTTPHeader *ParseHTTPHeader(char *Header)
{
	HTTPHeader *ResValue = (HTTPHeader *)calloc(1, sizeof(HTTPHeader));
	int Index;
	
	Index = FindInString(Header,  "\r\n");
	ResValue->StartingLine = (char *)calloc(1, Index + 1);
	memcpy(ResValue->StartingLine, Header, Index);

	ResValue->HeadersCount = 0;
	Header += Index + 2;

	while (*Header != '\r' && *(Header + 1) != '\n')
	{
		ResValue->Headers = (char **)realloc(ResValue->Headers, sizeof(char *) * (ResValue->HeadersCount + 1));
		Index = FindInString(Header, "\r\n");
		*(ResValue->Headers + ResValue->HeadersCount) = (char *)calloc(1, Index + 1);
		memcpy(*(ResValue->Headers + ResValue->HeadersCount), Header, Index);
		Header += Index + 2;
		(ResValue->HeadersCount)++;
	}

	Header += 2;

	ResValue->Content = NULL;
	ResValue->ContentLength = 0;
	if (strlen(Header))
	{
		ResValue->Content = (char *)calloc(1, strlen(Header) + 1);
		memcpy(ResValue->Content, Header, strlen(Header));
		ResValue->ContentLength = atoi(FindInHeadersList(ResValue, "content-length"));
	}

	int SecondIndex;

	Index = IndexOf(ResValue->StartingLine, 0, ' ');
	ResValue->Method = (char *)calloc(1, Index + 1);
	memcpy(ResValue->Method, ResValue->StartingLine, Index);

	SecondIndex = IndexOf(ResValue->StartingLine, Index + 1, ' ');
	ResValue->URI = (char *)calloc(1, SecondIndex - Index);
	memcpy(ResValue->URI, ResValue->StartingLine + Index + 1, SecondIndex - Index - 1);

	ResValue->Version = (char *)calloc(1, 9);
	memcpy(ResValue->Version, ResValue->StartingLine + SecondIndex + 1, 8);

	return ResValue;
}

void SendHTTP(SOCKET SendTo, char *HTTPType)
{
	if (send(SendTo, HTTPType, strlen(HTTPType), 0) == SOCKET_ERROR)
		printf("Error send %s: %d\n", HTTPType, WSAGetLastError());
}

char *GetDirectoryList(char *PathTo)
{
	char *Result = (char *)calloc(1, strlen(LIST_BEGIN) + 1);
	strcpy(Result, LIST_BEGIN);
	
	WIN32_FIND_DATAA FileInfo;
	HANDLE hFind;
		char *NewPath = (char *)calloc(1, strlen(PathTo) + 5);
		strcpy(NewPath, PathTo);
		strcat(NewPath, "/*.*");
		hFind = FindFirstFileA(NewPath, &FileInfo);	
		int OldSize, NewSize;
		OldSize = strlen(Result);
		do
		{
			if (strcmp(FileInfo.cFileName, ".") && strcmp(FileInfo.cFileName, ".."))
			{
				NewSize = OldSize + 21 + strlen("\"Type\": \"\",") + strlen("\"Name\": \"\"") + strlen(FileInfo.cFileName) + (FileInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ? strlen("Directory") : strlen("File"));
				Result = (char *)realloc(Result, NewSize);
				sprintf(Result + OldSize, "\t\t{\r\n\t\t\t\"Type\": \"%s\",\r\n\t\t\t\"Name\": \"%s\"\r\n\t\t},\r\n", (FileInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ? "Directory" : "File"), FileInfo.cFileName);
				OldSize = NewSize;
			}
		}
		while (FindNextFileA(hFind, &FileInfo));

		Result = (char *)realloc(Result, OldSize + strlen(LIST_END) + 1);
		sprintf(Result + OldSize - 3, "%s", LIST_END);
		return Result;
}

void ProcessGetRequest(HTTPHeader *Request, SOCKET Socket)
{
	char *PathTo = Realpath(SERVER_ROOT_DIRECTORY, Request->URI);
	HANDLE hFile;
	WIN32_FIND_DATAA *FileInfo = (WIN32_FIND_DATAA *)calloc(1, sizeof(WIN32_FIND_DATAA));
	if (PathTo[strlen(PathTo)-1] == '/')
		PathTo[strlen(PathTo)-1] = '\0';
	hFile = FindFirstFileA(PathTo, FileInfo);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		if (FileInfo->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			char *List = GetDirectoryList(PathTo), *Buf = (char *)calloc(1, DEFAULT_BUF_SIZE);
			sprintf(Buf, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", strlen(List));
			send(Socket, Buf, strlen(Buf), 0);
			send(Socket, List, strlen(List), 0);
			printf("%s structure sended\n", Request->URI);
		}
		else
		{
			FindClose(hFile);
			FILE *SrcFile = fopen(PathTo, "rb");
			char * Buf = (char *)calloc(1, DEFAULT_BUF_SIZE);
			LARGE_INTEGER Size;
				
			hFile = CreateFileA(PathTo, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hFile != INVALID_HANDLE_VALUE)
			{
				if (GetFileSizeEx(hFile, &Size))
				{
					if (Size.QuadPart > 0)
					{
						sprintf(Buf, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", Size.QuadPart);
						send(Socket, Buf, strlen(Buf), 0);
						while (!feof(SrcFile))
						{
							ZeroMemory(Buf, DEFAULT_BUF_SIZE);
							int Count = fread(Buf, 1, DEFAULT_BUF_SIZE, SrcFile);
							send(Socket, Buf, Count, 0);
						}
						printf("%s sended\n", Request->URI);
					}
					else
					{
						printf("File %s is empty\n", Request->URI);
						SendHTTP(Socket, NO_CONTENT);
					}
				}
				else
				{
					printf("%d\n", GetLastError());
				}
				CloseHandle(hFile);
			}
		}
	}
	else
	{
		if (GetLastError() == ERROR_FILE_NOT_FOUND)
		{
			printf("%s not found\n", Request->URI);
			SendHTTP(Socket, FILE_NOT_FOUND);
		}
		else
		{
			printf("Bad Request\n");
			SendHTTP(Socket, BAD_REQUEST);
		}
	}
	free(PathTo);
	free(FileInfo);
}

void ClearDir(char *PathToDir)
{
	char *PathToDirFiles;
	if (PathToDir[strlen(PathToDir) - 1] == '/')
	{
		PathToDirFiles = (char *)calloc(1, strlen(PathToDir) + 4);
		strcpy(PathToDirFiles, PathToDir);
		strcat(PathToDirFiles, "*.*");
	}
	else
	{
		PathToDirFiles = (char *)calloc(1, strlen(PathToDir) + 5);
		strcpy(PathToDirFiles, PathToDir);
		strcat(PathToDirFiles, "/*.*");
	}

	WIN32_FIND_DATAA FileInfo;
	HANDLE hFind = FindFirstFileA(PathToDirFiles, &FileInfo);
	do
	{
		if (strcmp(FileInfo.cFileName, ".") && strcmp(FileInfo.cFileName, ".."))
		{
			char *NewPath = (char *)calloc(1, strlen(PathToDir) + strlen(FileInfo.cFileName) + 2);
			strcpy(NewPath, PathToDir);
			strcat(NewPath, "/");
			strcat(NewPath, FileInfo.cFileName);
			if (FileInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				ClearDir(NewPath);
				if (!RemoveDirectory(NewPath))
				{
					printf("Fail to delete %s %d\n", NewPath, GetLastError());
					RemoveDirectory(NewPath);
				}
			}
			else
			{
				if (!DeleteFileA(NewPath))
					printf("Fail to delete %s %d\n", NewPath, GetLastError());
			}
			free(NewPath);
		}
	}
	while (FindNextFileA(hFind, &FileInfo));
	FindClose(hFind);

	free(PathToDirFiles);
}

void ProcessDeleteRequest(HTTPHeader *Request, SOCKET Socket)
{
	char *PathTo = Realpath(SERVER_ROOT_DIRECTORY, Request->URI);
	HANDLE hFile;
	WIN32_FIND_DATAA *FileInfo = (WIN32_FIND_DATAA *)calloc(1, sizeof(WIN32_FIND_DATAA));
	hFile = FindFirstFileA(PathTo, FileInfo);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		if (FileInfo->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			FindClose(hFile);
			ClearDir(PathTo);
			RemoveDirectory(PathTo);
			printf("%s deleted\n", Request->URI);
			SendHTTP(Socket, OK);
		}
		else
		{
			FindClose(hFile);
			if (DeleteFileA(PathTo))
			{
				printf("%s deleted\n", Request->URI);
				SendHTTP(Socket, OK);
			}
			else
			{
				DWORD ErrCode = GetLastError();
				if (ErrCode == ERROR_FILE_NOT_FOUND)
				{
					printf("%s not found\n", Request->URI);
					SendHTTP(Socket, FILE_NOT_FOUND);
				}
				else if (ErrCode == ERROR_ACCESS_DENIED)
				{
					printf("%s access denied\n", Request->URI);
					SendHTTP(Socket, ACCESS_DENIED);
				}
				else
				{
					printf("Bad Request\n");
					SendHTTP(Socket, BAD_REQUEST);
				}
			}
		}
	}
	else
	{
		if (GetLastError() == ERROR_FILE_NOT_FOUND)
		{
			printf("%s not found\n", Request->URI);
			SendHTTP(Socket, FILE_NOT_FOUND);
		}
		else
		{
			printf("Bad Request\n");
			SendHTTP(Socket, BAD_REQUEST);
		}
	}
	free(PathTo);
	free(FileInfo);
}

void ProcessHeadRequest(HTTPHeader *Request, SOCKET Socket)
{
	char *PathTo = Realpath(SERVER_ROOT_DIRECTORY, Request->URI);
	HANDLE hFind;
	WIN32_FIND_DATAA *FileInfo = (WIN32_FIND_DATAA *)calloc(1, sizeof(WIN32_FIND_DATAA));
	hFind = FindFirstFileA(PathTo, FileInfo);
	if (hFind != INVALID_HANDLE_VALUE)
	{
		if (!(FileInfo->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
		{
			char *Buf = (char *)calloc(1, DEFAULT_BUF_SIZE);

			HANDLE hFile = CreateFileA(PathTo, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			LARGE_INTEGER Size;
			GetFileSizeEx(hFile, &Size);

			sprintf(Buf, "HTTP/1.1 200 OK\r\nX-File-Size: %d\r\nX-Type: File\r\nX-Name: %s\r\n\r\n", Size.QuadPart, FileInfo->cFileName);
			send(Socket, Buf, strlen(Buf), 0);
		}
		else
		{
			printf("%s method not allowed\n", Request->URI);
			SendHTTP(Socket, METHOD_NOT_ALLOWED);
		}
	}
	else
	{
		if (GetLastError() == ERROR_FILE_NOT_FOUND)
		{
			printf("%s not found\n", Request->URI);
			SendHTTP(Socket, FILE_NOT_FOUND);
		}
		else
		{
			printf("Bad Request\n");
			SendHTTP(Socket, BAD_REQUEST);
		}
	}
	free(PathTo);
	free(FileInfo);
}

void CreateDirectoryPath(char *FullPath)
{
	char *Buf;
	int OldIndex = IndexOf(FullPath, strlen(SERVER_ROOT_DIRECTORY), '/'), NewIndex;
	while ((NewIndex = IndexOf(FullPath, OldIndex + 1, '/')) != -1)
	{
		Buf = (char *)calloc(1, NewIndex + 1);
		memcpy(Buf, FullPath, NewIndex);
		printf("%s\n", Buf);
		CreateDirectory(Buf, NULL);
		OldIndex = NewIndex;
		free(Buf);
	}
}

void ProcessPutRequest(HTTPHeader *Request, SOCKET Socket)
{
	char *PathTo = Realpath(SERVER_ROOT_DIRECTORY, Request->URI);
	if (FindInHeadersList(Request, "X-Copy-From") == NULL)
	{
		bool IsSuccess = true;
		int DataSize = Request->ContentLength;
		FILE *NewFile;
		if (DataSize == 0)
		{
			SendHTTP(Socket, BAD_REQUEST);
			return;
		}
		CreateDirectoryPath(PathTo);
		NewFile = fopen(PathTo, "wb");

		printf("%s", Request->Content);

		fwrite(Request->Content, 1, strlen(Request->Content), NewFile);
		DataSize -= strlen(Request->Content);
		
		char *DataBuf = (char *)calloc(1, DEFAULT_BUF_SIZE);
		while ((DataSize > 0) && IsSuccess)
		{
			int Count = recv(Socket, DataBuf, DEFAULT_BUF_SIZE, 0);
			if (Count == 0 || Count == SOCKET_ERROR)
			{
				IsSuccess = false;
			}
			else
			{
				fwrite(DataBuf, Count, 1, NewFile);
				DataSize -= Count;
				ZeroMemory(DataBuf, DEFAULT_BUF_SIZE);
			}
		}
		
		if (IsSuccess)
			SendHTTP(Socket, CREATED);
		free(DataBuf);
		fclose(NewFile);
	}
	else
	{
		char *PathTo = (char *)calloc(1, strlen(SERVER_ROOT_DIRECTORY) + strlen(Request->URI));
		strcpy(PathTo, SERVER_ROOT_DIRECTORY);
		strcat(PathTo, Request->URI);
		char *PathFrom = (char *)calloc(1, strlen(SERVER_ROOT_DIRECTORY) + strlen(FindInHeadersList(Request, "X-Copy-From")));
		strcpy(PathFrom, SERVER_ROOT_DIRECTORY);
		strcat(PathFrom, FindInHeadersList(Request, "X-Copy-From"));
		printf("%s %s\n", PathTo, PathFrom);
		if (CopyFile(PathFrom, PathTo, false) == 0)
		{
			DWORD ErrCode = GetLastError();
			if (ErrCode == ERROR_ACCESS_DENIED)
				SendHTTP(Socket, ACCESS_DENIED);
			else if (ErrCode == ERROR_PATH_NOT_FOUND || ErrCode == ERROR_FILE_NOT_FOUND)
				SendHTTP(Socket, FILE_NOT_FOUND);
			else 
				SendHTTP(Socket, BAD_REQUEST);
		}
		else
			SendHTTP(Socket, CREATED);
	}
}

void CleanUpHeaderMemory(HTTPHeader *Header)
{
	int i;
	free(Header->Method);
	free(Header->StartingLine);
	free(Header->URI);
	free(Header->Version);
	
	for (i=0; i<Header->HeadersCount; i++)
		free(*(Header->Headers + i));

	free(Header->Headers);
	free(Header);
}

DWORD WINAPI ProcessingThread(LPVOID lpParam)
{
	SOCKET AcceptedSocket = *(SOCKET *)lpParam;
	char *RecvBuf = (char *)calloc(1, DEFAULT_BUF_SIZE);
	HTTPHeader *Header;
	recv(AcceptedSocket, RecvBuf, DEFAULT_BUF_SIZE, 0);
	Header = ParseHTTPHeader(RecvBuf);
	printf("%s\n", Header->StartingLine);
	if (!strcmp(Header->Method, "GET"))
		ProcessGetRequest(Header, AcceptedSocket);
	else if (!strcmp(Header->Method, "DELETE"))
		ProcessDeleteRequest(Header, AcceptedSocket);
	else if (!strcmp(Header->Method, "HEAD"))
		ProcessHeadRequest(Header, AcceptedSocket);
	else if (!strcmp(Header->Method, "PUT"))
		ProcessPutRequest(Header, AcceptedSocket);
	else
		SendHTTP(AcceptedSocket, NOT_IMPLEMENTED);
	CleanUpHeaderMemory(Header);
		
	shutdown(AcceptedSocket, SD_BOTH);
	closesocket(AcceptedSocket);
	free(RecvBuf);
	return 0;
}

int main(int argc, char **argv)
{
	WSADATA wsaData;

	if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0)
	{
		printf("WSAStartup return error: %d\n", WSAGetLastError());
		Sleep(SLEEP_TIME);
		return 1;
	}
	
	SOCKET ListeningSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ListeningSocket == INVALID_SOCKET)
	{
		printf("ListeningSocket: socket return error: %d\n", WSAGetLastError());
		Sleep(SLEEP_TIME);
		return 1;
	}

	sockaddr_in *ListeningAddress = (sockaddr_in *)calloc(1, sizeof(sockaddr_in));
	ListeningAddress->sin_addr.s_addr = inet_addr(DEFAULT_IP);
	ListeningAddress->sin_family = AF_INET;
	ListeningAddress->sin_port = htons(DEFAULT_PORT);

	if (bind(ListeningSocket, (sockaddr *)ListeningAddress, sizeof(sockaddr_in)) == SOCKET_ERROR)
	{
		printf("ListeningSocket: bind return error: %d\n", WSAGetLastError());
		Sleep(SLEEP_TIME);
		return 1;
	}

	if (listen(ListeningSocket, SOMAXCONN) == SOCKET_ERROR)
	{
		printf("ListeningSocket: listen return error: %d\n", WSAGetLastError());
		Sleep(SLEEP_TIME);
		return 1;
	}
	
	sockaddr_in *AcceptedAddress = (sockaddr_in *)calloc(1, sizeof(sockaddr_in));
	int AddressSize = sizeof(sockaddr_in);
	SOCKET AcceptedSocket;
	printf("Waiting...\n");
	while (AcceptedSocket = accept(ListeningSocket, (sockaddr *)AcceptedAddress, &AddressSize))
	{
		if (AcceptedSocket != INVALID_SOCKET)
		{
			CreateThread(NULL, 0, &ProcessingThread, &AcceptedSocket, 0, NULL);
		}
		else
		{
			printf("accept return error: %d\n", WSAGetLastError());
		}
	}
	return 0;
}