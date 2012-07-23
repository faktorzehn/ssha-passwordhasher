/**
 *
 * Copyright (c) 2009 Mauri Marco - All rights reserved.
 * Copyright (c) 2012 FaktorZehn AG - All rights reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
**/

#include "stdafx.h"
#include "acl.h"
#include <shlobj.h>
#include <WinCrypt.h>
#include <ctype.h>


#define SHA1_HASH_LEN 20
#define SHA1_SALT_LEN 8

extern "C"{
#include "base64.h"
}


   #ifndef STATUS_SUCCESS
   #define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
   #define STATUS_OBJECT_NAME_NOT_FOUND    ((NTSTATUS)0xC0000034L)
   #define STATUS_INVALID_SID              ((NTSTATUS)0xC0000078L)
   #endif




BOOLEAN NTAPI InitializeChangeNotify();
NTSTATUS NTAPI PasswordChangeNotify(PUNICODE_STRING,ULONG,PUNICODE_STRING);
BOOLEAN NTAPI PasswordFilter(PUNICODE_STRING,PUNICODE_STRING,PUNICODE_STRING,BOOLEAN);

wchar_t* loadSetting(wchar_t* path,wchar_t* key,wchar_t* buffer, int bufferLen){
    int charRead = GetPrivateProfileString(L"Main",key,NULL,buffer,bufferLen,path);
    wchar_t* out =(wchar_t*) malloc((charRead + 1) * sizeof(wchar_t));
    wcscpy(out,buffer);
    return out;
}

bool loadConfig(){
    wchar_t inipath[MAX_PATH + 1];
    if(!SUCCEEDED(SHGetFolderPath(NULL,CSIDL_COMMON_APPDATA|CSIDL_FLAG_CREATE, NULL, 0, inipath))) return false;
    wchar_t* path = lstrcat(inipath,L"\\HashingPasswordFilter.ini");
    wchar_t buffer[MAX_PATH + 1];
    if (path==NULL)return false;
    configuration.ldapAdminBindDn = loadSetting(path,L"ldapAdminBindDn",buffer,MAX_PATH + 1);
    configuration.ldapAdminPasswd = loadSetting(path,L"ldapAdminPasswd",buffer,MAX_PATH + 1);
    configuration.ldapSearchBaseDn = loadSetting(path,L"ldapSearchBaseDn",buffer,MAX_PATH + 1);
    
	
	wchar_t* temp = loadSetting(path,L"processPath",buffer,MAX_PATH + 1);
    int cmdLineLen = _scwprintf(PROCESS_COMMAND_LINE_FORMAT_STRING,temp,PROCESS_COMMAND_LINE_PARAMETERS,
        configuration.proxyAddress, configuration.proxyUser, configuration.proxyPassword) + 1;
    configuration.processCommandLine = (wchar_t*)malloc(cmdLineLen * sizeof(wchar_t));
    swprintf(configuration.processCommandLine,cmdLineLen,PROCESS_COMMAND_LINE_FORMAT_STRING,temp,
        PROCESS_COMMAND_LINE_PARAMETERS, configuration.proxyAddress, configuration.proxyUser,
        configuration.proxyPassword);
    free(temp);
    configuration.processPasswd = loadSetting(path,L"processPasswd",buffer,MAX_PATH + 1);
    configuration.processUser = loadSetting(path,L"processUser",buffer,MAX_PATH + 1);

    return true;
}

Configuration configuration;
bool configured = false;

//This method calculate the Salted SHA-1 hash of the given password
//password must be a null terminated string
//hash must be a preallocated buffer of at least 100 characters (99 character + null)
void hashPassword(char* password, char* hash){
	HCRYPTPROV   hCryptProv;
	HCRYPTHASH   hCryptHash;
	char salt[SHA1_SALT_LEN + 1];
	char saltedpassword[100];
	BYTE bytehash[100];
	char resulthash[100];
	
	BYTE  bHashValue[SHA1_HASH_LEN];
	DWORD dwSize = SHA1_HASH_LEN;
 
	
	memset(salt,'\0', SHA1_SALT_LEN +1 * sizeof(char));
	memset(saltedpassword,'\0', 100 * sizeof(char));
	memset(bytehash,'\0', 100* sizeof(char));
	memset(resulthash,'\0', 100* sizeof(char));
	memset(hash,'\0', 100 * sizeof(char));
	

	// get random alphanumeric 8-byte salt
	CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
	CryptGenRandom(hCryptProv, SHA1_SALT_LEN , (BYTE*)salt);
	CryptReleaseContext(hCryptProv, 0);
	
	// postfix hex-salt to password
	sprintf(saltedpassword,"%s%s",password,salt);

	// hash it with wincrypt-sha1
	if ( CryptAcquireContext(&hCryptProv, NULL, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) ) {
		if (CryptCreateHash(hCryptProv, CALG_SHA1, 0, 0, &hCryptHash) ){
			if (CryptHashData(hCryptHash, (BYTE*) saltedpassword, strlen(saltedpassword), 0) ){
				if (CryptGetHashParam(hCryptHash, HP_HASHVAL, bHashValue, &dwSize, 0) ) {
				}else{
					writeMessageToLog(L"ERROR: couldn't read (already created) hash ...");
				}
			}else{
				writeMessageToLog(L"ERROR: couldn't hash the salted password ...");
			}
		}else{
			writeMessageToLog(L"ERROR: couldn't create SHA1-Hash with CryptCreateHash ...");
		}
	}else{
		writeMessageToLog(L"ERROR: couldn't acquire WinCryptContext...");
	}


	CryptDestroyHash(hCryptHash);
	CryptReleaseContext(hCryptProv, 0);

	// copy salt after byte-hash 
	for (int i=0; i < SHA1_HASH_LEN; i++){
		printf("",i); // please dear vc++, don't optimize me away
		bytehash[i] = bHashValue[i];
	}

	for (int i=0; i < SHA1_SALT_LEN; i++){
		printf("",i); // please dear vc++, don't optimize me away
		bytehash[SHA1_HASH_LEN+i] = salt[i];
	}
	
	// to base64
	if ( base64_encode((unsigned char*)bytehash, SHA1_HASH_LEN + SHA1_SALT_LEN, resulthash, 100) ) {
		writeMessageToLog(L"ERROR: base64 encode of salted hash failed...");
	}
	
	strncat(hash,"{SSHA}",6);
	strncat(hash,resulthash,strlen(resulthash));

	// secure wipe salted password
	SecureZeroMemory(saltedpassword,strlen(saltedpassword));
	
	return;
}

bool setFilePermissions(){
    wchar_t systempath[MAX_PATH + 1];
    if(!SUCCEEDED(SHGetFolderPath(NULL,CSIDL_COMMON_APPDATA|CSIDL_FLAG_CREATE, NULL, 0, systempath))) return false;
    
    wchar_t originaldll[]=LOG_FILE_NAME;
	wchar_t *totalpath=lstrcat(systempath,originaldll);
    if (totalpath == NULL) return false;
    writeMessageToLog(L"Setting write permission for user %s", configuration.processUser); 
    bool result = AddAccessRights(totalpath,configuration.processUser, GENERIC_ALL);
    if (!result){
        writeMessageToLog(L"Unable to set write permission for user %s, the log could be incomplete from now on",configuration.processUser);
        return FALSE;
    } else {
        writeMessageToLog(L"Write permission for user %s set", configuration.processUser);
        return TRUE;
    }
}

bool initializeFilter(){
    bool result = loadConfig();
    return result;
}

//no initialization necessary
BOOLEAN NTAPI InitializeChangeNotify()
{   
    writeLog(L"Starting HashingPasswordFilter");
    if (initializeFilter()){
        writeLog(L"HashingPasswordFilter initialized");
        return TRUE;
    } else {
        writeLog(L"HashingPasswordFilter: initialization failed");
        return FALSE;
    }
}


//the event: password has changed succesfully
NTSTATUS NTAPI PasswordChangeNotify(PUNICODE_STRING UserName,ULONG RelativeId,PUNICODE_STRING NewPassword)
{
	
    if (!configured){
        configured = setFilePermissions();
    }
	int nLen=0;
    bool result;
	
    //copy username
    int userLength = UserName->Length/ sizeof(wchar_t);
    wchar_t* username = (wchar_t*)malloc((userLength + 1) * sizeof(wchar_t));
    wchar_t* z = wcsncpy(username,UserName->Buffer,userLength);
    //set the last character to null
    username[userLength] = NULL;

    //convert the password from widechar to utf-8
    int passwordLength = NewPassword->Length/ sizeof(wchar_t);
    nLen = WideCharToMultiByte(CP_UTF8, 0, NewPassword->Buffer, passwordLength, 0, 0, 0, 0);
    char* password = (char*)malloc((nLen + 1) * sizeof(char));
    nLen = WideCharToMultiByte(CP_UTF8, 0, NewPassword->Buffer,passwordLength, password, nLen, 0, 0);
    
    //set the last character to null
    password[nLen] = NULL;

    //allocate and calculate the hash
    char hash[100];
    hashPassword(password, hash);

    wchar_t w_hash[100];
    mbstowcs_s(0, w_hash, hash, _TRUNCATE);

    //try to write the hash to ldap
    result = writeHashToLdap(username, w_hash);

    if (result){
        writeMessageToLog(CHANGE_PASSWORD_MESSAGE,username);
    }
    else
        writeMessageToLog(L"Change failed for user \"%s\"",username);


    //zero the password
    SecureZeroMemory(password,nLen);

    //free the memory
	free(username);
	free(password);

    
    //can I return something else in case of error?
	return STATUS_SUCCESS;

}

//don't apply any password policy
BOOLEAN NTAPI PasswordFilter(PUNICODE_STRING AccountName,PUNICODE_STRING FullName,PUNICODE_STRING Password,BOOLEAN SetOperation)
{

   return TRUE;

}


