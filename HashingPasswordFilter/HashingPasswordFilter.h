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

#ifndef _HASH_FILTER_H_
#define _HASH_FILTER_H_
struct Configuration{
    //DN and password of user to log toActive directory
    wchar_t* ldapAdminBindDn;
    wchar_t* ldapAdminPasswd;
    //LDAP query to used to find users
    wchar_t* ldapSearchBaseDn;
    wchar_t* appsDomain;
    //User and password of admin account of google apps
    wchar_t* appsAdmin;
    wchar_t* appsPasswd;
    //user and password of local account used to run the sync program
    wchar_t* processUser;
    wchar_t* processPasswd;
    wchar_t* processCommandLine;
    //proxy settings
    bool useProxy;
    wchar_t* proxyAddress;
    wchar_t* proxyUser;
    wchar_t*proxyPassword;

};
extern Configuration configuration;

#define PROCESS_COMMAND_LINE_FORMAT_STRING L"\"%s\" %s %s %s %s"
#define PROCESS_COMMAND_LINE_PARAMETERS L"%s %s \"%s\" \"%s\" %s SHA-1"
#endif
