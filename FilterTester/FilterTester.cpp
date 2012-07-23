/**
 *
 * Copyright (c) 2009 Mauri Marco All rights reserved.
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

#define USER_TO_CHANGE L"pluto"
#define NEW_PASSWORD L"123456"

typedef BOOLEAN (NTAPI *pi)();
typedef NTSTATUS (NTAPI *pcn)(PUNICODE_STRING,ULONG,PUNICODE_STRING);
typedef BOOLEAN (NTAPI *pf)(PUNICODE_STRING,PUNICODE_STRING,PUNICODE_STRING,BOOLEAN);

int main(int argc, char* argv[])
{
    HINSTANCE hDll;

    //Load filter
    if( !(hDll = LoadLibrary( L"HashingPasswordFilter.dll" )) ) {
        return printf("Cannot load filter");
    }

    pi Init = (pi)GetProcAddress( hDll, "InitializeChangeNotify" );
    if( !Init )  return printf("InitializeChangeNotify error");
    else 
    {
        if(Init()) printf("Init passt\n");
        else return printf("Init failed ");
    }

    pcn Change= (pcn)GetProcAddress( hDll, "PasswordChangeNotify" );
    if( !Change)  return printf("PasswordChangeNotify error");
    else
    {
        int nLen;
        UNICODE_STRING unicode_username;
        UNICODE_STRING unicode_password;

        //Compose the UNICODE_STRING for username
        LPWSTR username = USER_TO_CHANGE;
        nLen = wcslen(username);
        unicode_username.Length=nLen* sizeof (WCHAR);
        unicode_username.MaximumLength=(nLen+1) *sizeof(WCHAR);
        unicode_username.Buffer=username;


        //Compose the UNICODE_STRING for password
        LPWSTR password = NEW_PASSWORD;
        nLen = wcslen(password);
        unicode_password.Length=nLen* sizeof (WCHAR);
        unicode_password.MaximumLength=(nLen+1) *sizeof(WCHAR);
        unicode_password.Buffer=password;

        //Call the PasswordChangeNotify of the filter dll: parameters by reference as told in MSDN
        NTSTATUS result = Change(&unicode_username,600,&unicode_password);
        printf("PasswordChangeNotify says: %d",result);

    }

    pf Filter = (pf)GetProcAddress( hDll, "PasswordFilter" );
    if( !Filter)  return printf("PasswordFilter error");
    _getch();
    return 0;
}

