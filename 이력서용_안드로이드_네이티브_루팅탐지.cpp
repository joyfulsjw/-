#include <jni.h>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <android/log.h>
#include <unistd.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>


JavaVM * glpVM = NULL;
bool is_ARM64 = true;
const char* g_file_dir;
const char* g_NativeLibDir;
const char * g_PackageResourcePath;
const char * g_pkgName;
const char * g_cache_dir;

void * libc_handle = 0;
int (*globalfunc_stat)(const char *, struct stat *);
FILE* (*globalfunc_fopen)(const char *, const char *);
int (*globalfunc_fclose)(FILE*);
int (*globalfunc_getpid)();
int (*globalfunc_kill)(int, int);
int (*globalfunc_pthread_create)(pthread_t *, const pthread_attr_t *, void *(*)(void *) ,void *);
int (*globalfunc_usleep)(useconds_t);
void * (*globalfunc_malloc)(size_t);
void * (*globalfunc_memset)(void *, int, size_t);
int (*globalfunc_fgetc)(FILE *);
int (*globalfunc_unlink)(const char *);
int (*globalfunc_open)(const char *, int, int);

unsigned int progresscode = 0xA;
char exitbuf[2] = {0,0};
unsigned int progresscode2 = 0xB;
char retstr[56] = {0,};
unsigned int progresscode3 = 0xC;
unsigned int riskcode = 0;
char encarr[56][76]= {
        "63607968",
        "54292a33761307",
        "4545415d51",
        "76",
        "5a253c35170b",
        "25282c13071d",
        "435b502a",
        "564f38171feec0e6ad919d6c5652",
        "7b111217e2b5",
        "3147331302e9cf97b686937e09",
        "04312003f3fbd8e39098784610",
        "3b583b2a04e2f39aae8a943e",
        "0f5c311ce1b7dca783997c07",
        "ff896b53254e12f4dbb49e20582416ac",
        "5345",
        "f8c5b5a5906766",
        "e9fbd7afaf99",
        "ffd2d4aa838d",
        "0f2601f087b9836d5b3700b9d9be9e7a",
        "e983633741fbae8d653345e4d19f774e39e3cf947e541b",
        "7a01e0d0fe856a582802ff",
        "22d391b5481b3dcd92bc5a1935dbf0a45b7223ad8b",
        "44c4b47e5e5bcdbf672952d188717ff2d4804f35e7aa8e5b4df5ac655e1fca",
        "eadaad849d",
        "d5b1936b5f39",
        "f0d3b7847d",
        "fdc8bc9973",
        "ab8664452508",
        "a18b7d413102",
        "a1816a573bef",
        "eed8a98b",
        "c4b78c452a",
        "3604",
        "bdb182702d52c2be7e161df9af8d",
        "f060331dc0fb76530bfee6974a2cfe",
        "1903d3976a3dffe36429149b804d16efa2713ea493995c",
        "e371411dd0bf7d691edb863124f9e0db4904",
        "20704a90e03a0050b0b385",
        "5fedae934679f7c7",
        "4be4a8945e4cfba89b4611fe",
        "db5919e5b8675541c6b37e690fc7",
        "67f3c1835c05f5ff702211dec7532d",
        "f9af7560e1b26560e4a57425e3b46524a0803e8f05fc",
        "6a3ff1bd224c15dec67c34feb966",
        "2d62ba8ec21e53a6f832",
        "176da6fb3a0d4397ea25",
        "d01c04f9aa",
        "15f1",
        "6a21f6a12f2ce1ae676fd3b97334e5ad",
        "b8665f17",
        "fb560bc9995752a86a3cfecf741ac7952dedea3109",
        "7b3de0917f3be1b48f",
        "48915c09ae7c02a7491cff4befb644ed8e4cbf9a25ebdf09d38b35dc4d39de6907dd6253",
        "443bf3a469",
        "1dca8c7536ff",
        "835707f3"
};

unsigned int NUM_OF_PATH = 6;
unsigned int START_OF_PATH = 8;
unsigned int riskcode2 = 0;
unsigned int riskcode3 = 0;
unsigned int NUM_OF_BINARY = 3;
unsigned int START_OF_BINARY = 14;


char * function_decrypt_string(int index)
{
    int declen = strlen(encarr[index])/2;
    int xor_addval_imsi = declen + index;
    int xor_addval = (int)(xor_addval_imsi & 0xFF);
    int xor_val_imsi = xor_addval * declen;
    int xor_val = (int)(xor_val_imsi & 0xFF);
    for(int i = 0; i < declen; i++)
    {
        int byte1 = (int)encarr[index][i*2];
        int diffbyte1 = 0;
        int byte2 = (int)encarr[index][i*2 + 1];
        int diffbyte2 = 0;
        int imsi = 0;

        if(!isalpha(byte1))
        {
            diffbyte1 = (int)(byte1 - 0x30);
        }
        else
        {
            diffbyte1 = (int)(byte1 - 0x57);
        }

        if(!isalpha(byte2))
        {
            diffbyte2 = (int)(byte2 - 0x30);
        }
        else
        {
            diffbyte2 = (int)(byte2 - 0x57);
        }
        imsi = (int)((diffbyte1 * 0x10 + diffbyte2) & 0xFF);
        retstr[i] = (char) ((imsi ^ xor_val)&0xff);
        xor_val = (int)((xor_val + xor_addval)&0xff);
    }
    retstr[declen] = 0;
    return retstr;
}

void * function_dlopen_libc()
{
    void * handle = dlopen(function_decrypt_string(1), RTLD_NOW);
    libc_handle = handle;
    if(libc_handle)
    {
        dlclose(handle);
    }
    else
    {
    }
    return handle;
}

void * function_dlsym(char * name)
{
    if(libc_handle)
    {
        return dlsym((void *)libc_handle, name);
    }
    function_dlopen_libc();
    return dlsym((void *)libc_handle, name);
}


bool exists(const char * fname)
{
    struct stat existstat;
    FILE * file;
    if(!globalfunc_stat(fname, &existstat)) {
        if ((file = (FILE *)globalfunc_fopen(fname, function_decrypt_string(3)))) {
            globalfunc_fclose(file);
            return true;
        }
    }
    return false;
}

void pthread_call(void *(*func)(void*))
{
    pthread_t thid;
    pthread_attr_t pa;
    pthread_attr_init(&pa);
    pthread_attr_setdetachstate(&pa, PTHREAD_CREATE_DETACHED);
    if(globalfunc_pthread_create != NULL)
    {
        globalfunc_pthread_create(&thid, &pa, func, NULL);
    }
}

char * compare_string(char * a1, char * a2)
{
    char * a1ptr = a1;
    char * a2ptr = a2;
    if(!*a2)
    {
        return a1;
    }
    if(*a1)
    {
        do{
            if(*a1 == *a2)
            {
                a2ptr = a2;
                a1ptr = a1;
                char v2;
                char v1;
                while(1)
                {
                    v2 = *(++a2ptr);
                    v1 = *(++a1ptr);
                    if(!v2){
                        return a1;
                    }
                    if(v1 != v2)
                    {
                        break;
                    }
                }
            }
            a1++;
        }while(*a1);
    }
    return 0;
}

char * concat_string(char * a1, char * a2)
{
    char * v1 = a1;
    char * v2 = a2;
    int a1length = 0;
    int a2length = 0;

    if(a1)
    {
        while(*v1++)
        {;}
        a1length = v1 - a1 - 1;
        if(!a2)
        {
            a1[a1length] = 0;
            return a1;
        }
    }
    while(*v2++)
    {;}
    a2length = v2 - a2 - 1;
    if(!a2length)
    {
        a1[a1length + a2length] = 0;
        return a1;
    }

    char * v8 = &a1[a1length];
    int v9 = a2length -1;

    if(a2length> 0xF && (a2 >= &a1[a1length+16] || v8 >= a2 + 16))
    {
        int v10 = 0;
        int v11 = sizeof(long);
        if(v11 == 8)
        {
            v10 = (a2length >> 3) + 1;
        }
        else
        {
            v10 = (a2length >> 2) + 1;
        }
        char * v12 = a2;
        char * v13 = &a1[a1length];
        int v14 = 0;
        do
        {
            unsigned long v15 = *(unsigned long *)v12;

            *(unsigned long *)v13 = v15;
            ++v14;
            v12 += v11;
            v13 += v11;
            v8 += v11;
            a2 += v11;
            v9 -= v11;
        }while(v10 - 1 > v14);

        *v8 = *a2;
        if(v9 > 0)
        {
            v8[1] = a2[1];
            if(v9 != 1)
            {
                v8[2] = a2[2];
                if ( v9 != 2 )
                {
                    v8[3] = a2[3];
                    if ( v9 != 3 )
                    {
                        v8[4] = a2[4];
                        if( v9 != 4 )
                        {
                            v8[5] = a2[5];
                            if( v9 != 5 )
                            {
                                v8[6] = a2[6];
                                if( v9 != 6 )
                                {
                                    v8[7] = a2[7];
                                    if( v9 != 7 )
                                    {
                                        v8[8] = a2[8];
                                        if( v9 != 8 )
                                        {
                                            v8[9] = a2[9];
                                            if( v9 != 9 )
                                            {
                                                v8[10] = a2[10];
                                                if( v9 != 10 )
                                                {
                                                    v8[11] = a2[11];
                                                    if( v9 != 11 )
                                                    {
                                                        v8[12] = a2[12];
                                                        if( v9 != 12 )
                                                        {
                                                            v8[13] = a2[13];
                                                            if( v9 != 13 )
                                                            {
                                                                v8[14] = a2[14];
                                                                if( v9 != 14 )
                                                                {
                                                                    v8[15] = a2[15];
                                                                    if( v9 != 15 )
                                                                    {
                                                                        v8[16] = a2[16];
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        a1[a1length + a2length] = 0;
        return a1;
    }

    int v16 = 0;
    do
    {
        v8[v16] = a2[v16];
        v16++;
    }while(v16 != a2length);
    a1[a1length + a2length] = 0;
    return a1;
}

char * makearr(char * a1, char * a2)
{
    if(a2)
    {
        char * v2 = a2;
        int a2length = 0;
        while(*v2++)
        {;}
        a2length = v2 - a2 - 1;
        int v9 = a2length -1;
        if(!a2length)
        {
            a1[a2length] = 0;
            return a1;
        }


        if(a2length> 0xF && (a2 >= a1+16 || a1 >= a2 + 16))
        {
            int v10 = 0;
            int v11 = sizeof(long);
            if(v11 == 8)
            {
                v10 = (a2length >> 3) + 1;
            }
            else
            {
                v10 = (a2length >> 2) + 1;
            }
            char * v12 = a2;
            char * v13 = a1;
            int v14 = 0;
            do
            {
                unsigned long v15 = *(unsigned long *)v12;
                *(unsigned long *)v13 = v15;
                ++v14;
                v12 += v11;
                v13 += v11;
                a2 += v11;
                v9 -= v11;
            }while(v10 - 1 > v14);

            *v13 = *a2;
            if(v9 > 0)
            {
                v13[1] = a2[1];
                if(v9 != 1)
                {
                    v13[2] = a2[2];
                    if ( v9 != 2 )
                    {
                        v13[3] = a2[3];
                        if ( v9 != 3 )
                        {
                            v13[4] = a2[4];
                            if( v9 != 4 )
                            {
                                v13[5] = a2[5];
                                if( v9 != 5 )
                                {
                                    v13[6] = a2[6];
                                    if( v9 != 6 )
                                    {
                                        v13[7] = a2[7];
                                        if( v9 != 7 )
                                        {
                                            v13[8] = a2[8];
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            a1[a2length] = 0;
            return a1;
        }

        int v16 = 0;
        do
        {
            a1[v16] = a2[v16];
            v16++;
        }while(v16 != a2length);
        a1[a2length] = 0;
        return a1;
    }

    *a1 = 0;
    return a1;
}




void * rootcheckthread1(void *arg)
{
    for(int i = 0; i < NUM_OF_PATH; i++)
    {
        char path[256];
        globalfunc_memset(path, 0, sizeof(path));
        makearr(path, function_decrypt_string(START_OF_PATH + i));
        for(int j = 0; j < NUM_OF_BINARY; j++)
        {
            char tmp[256];
            globalfunc_memset(tmp, 0, sizeof(tmp));
            makearr(tmp, path);
            if(exists(concat_string(tmp, function_decrypt_string(START_OF_BINARY + j))))
            {
                riskcode = riskcode ^ 40;
                while(1){
                    globalfunc_usleep(5000000);
                    for(int i = 0; i <= riskcode*progresscode; i++)
                    {
                        exitbuf[i] = 'A';
                    }
                }
            }
        }
    }
    progresscode = progresscode ^ 0x60040;
    return 0;
}


void * rootcheckthread2(void *arg)
{

    struct dirent **namelist;
    int count;
    int idx = 0;
    char path[256];
    globalfunc_memset(path, 0, sizeof(path));
    makearr(path, function_decrypt_string(8));

    if((count = scandir(path, &namelist, NULL, alphasort)) == -1) {
    }
    else
    {
        idx = count - 1;
        for(idx; idx > 0; idx--){
            if(!(strcmp(namelist[idx]->d_name, function_decrypt_string(14)))){
                riskcode = riskcode ^ 400;
                while(1){
                    globalfunc_usleep(5000000);
                    for(int i = 0; i <= riskcode*progresscode; i++)
                    {
                        exitbuf[i] = 'A';
                    }
                }
            }
        }
    }
    progresscode = progresscode ^ 0x4000;
    return 0;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_eqst_lms_solution3_SplashActivity_illillillilliillillillil(JNIEnv* env, jobject jobj /* this */)
{
    pthread_call(rootcheckthread1);
    pthread_call(rootcheckthread2);
    return 0;
}



void * magiskcheckthread1(void *arg)
{
    int fd;
    char path[128];
    globalfunc_memset(path, 0, sizeof(path));
    makearr(path, function_decrypt_string(22));
    fd = globalfunc_open(path, 0, 0);
    if(fd != -1)
    {
        riskcode2 = riskcode2 ^ 4000;
        while(1){
            globalfunc_usleep(5000000);
            for(int i = 0; i <= riskcode2*progresscode2; i++)
            {
                exitbuf[i] = 'L';
            }
        }
    }

    progresscode2 = progresscode2 ^ 0x4000;
    return 0;
}




extern "C" JNIEXPORT jboolean JNICALL
Java_com_eqst_lms_solution3_SplashActivity_illillillil1iillillillil(JNIEnv* env, jobject jobj /* this */)
{
    pthread_call(magiskcheckthread1);
    return 0;
}

void * usbcheckthread2(void *arg)
{
    int usbrisk = 0;

    FILE * file2;
    file2 = (FILE *)globalfunc_fopen(function_decrypt_string(18), "r");
    if(file2) {
        usbrisk = 1;
    }
    FILE * file;
    char path[128];
    globalfunc_memset(path, 0, sizeof(path));
    makearr(path, function_decrypt_string(19));
    concat_string(path, function_decrypt_string(20));
    file = (FILE *)globalfunc_fopen(path, "r");
    if(file)
    {
        char buf[128];
        char *ptr = buf;
        globalfunc_memset(buf, 0, 128);
        char chr = 0;
        while(1)
        {
            chr = globalfunc_fgetc(file);
            if(chr == -1 || ptr == &buf[127])
            {
                break;
            }
            *ptr++ = chr;
        }
        if(compare_string(buf, function_decrypt_string(21)))
        {
            if(usbrisk)
            {
                riskcode3 = riskcode3 ^ 40;
                while(1){
                    globalfunc_usleep(5000000);
                    for(int i = 0; i <= riskcode3*progresscode3; i++)
                    {
                        exitbuf[i] = 'G';
                    }
                }
            }
        }
        globalfunc_fclose(file);
    }
    progresscode3 = progresscode3 ^ 0x800;
    return 0;
}


extern "C" JNIEXPORT jboolean JNICALL
Java_com_eqst_lms_solution3_SplashActivity_illillillil1iilllilil1il(JNIEnv* env, jobject jobj /* this */)
{
    pthread_call(usbcheckthread2);
    return 0;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_eqst_lms_solution3_MainActivity_illl1lillil1iil1lilil1il(JNIEnv* env, jobject context /* this */)
{
    jstring packageName;
    jobject packageManagerObj;
    jobject packageInfoObj;
    jclass contextClass = env->GetObjectClass(context);
    jmethodID getPackageNameMid = env->GetMethodID( contextClass, "getPackageName", "()Ljava/lang/String;");
    jmethodID getPackageManager =  env->GetMethodID( contextClass, "getPackageManager", "()Landroid/content/pm/PackageManager;");

    jclass packageManagerClass = env->FindClass("android/content/pm/PackageManager");
    jmethodID getPackageInfo = env->GetMethodID( packageManagerClass, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");

    jclass packageInfoClass = env->FindClass("android/content/pm/PackageInfo");
    jfieldID signaturesFid = env->GetFieldID( packageInfoClass, "signatures", "[Landroid/content/pm/Signature;");

    jclass signatureClass = env->FindClass("android/content/pm/Signature");
    jmethodID signatureToByteArrayMid = env->GetMethodID( signatureClass, "toByteArray", "()[B");

    jclass messageDigestClass = env->FindClass("java/security/MessageDigest");
    jmethodID messageDigestUpdateMid = env->GetMethodID( messageDigestClass, "update", "([B)V");
    jmethodID getMessageDigestInstanceMid  = env->GetStaticMethodID( messageDigestClass, "getInstance", "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    jmethodID digestMid = env->GetMethodID( messageDigestClass,"digest", "()[B");

    jclass base64Class = env->FindClass("android/util/Base64");
    jmethodID encodeToStringMid = env->GetStaticMethodID( base64Class,"encodeToString", "([BI)Ljava/lang/String;");

    packageName =  (jstring)env->CallObjectMethod( context, getPackageNameMid);

    packageManagerObj = env->CallObjectMethod(context, getPackageManager);
    // PackageManager.GET_SIGNATURES = 0x40
    packageInfoObj = env->CallObjectMethod( packageManagerObj,getPackageInfo, packageName, 0x40);
    jobjectArray signatures = (jobjectArray)env->GetObjectField( packageInfoObj, signaturesFid);
    //int signatureLength =  env->GetArrayLength(signatures);
    jobject signatureObj = env->GetObjectArrayElement(signatures, 0);
    jobject messageDigestObj  = env->CallStaticObjectMethod(messageDigestClass, getMessageDigestInstanceMid, env->NewStringUTF("SHA1"));
    env->CallVoidMethod(messageDigestObj, messageDigestUpdateMid, env->CallObjectMethod( signatureObj,signatureToByteArrayMid));

    jstring signatureHash = (jstring)env->CallStaticObjectMethod( base64Class, encodeToStringMid,env->CallObjectMethod( messageDigestObj, digestMid, signatureObj), 0);

    return signatureHash;
}


char iIiIiIiIiI [16] = {0,};
typedef union {
    JNIEnv* env;
    void* venv;
} UnionJNIEnvToVoid;

int getlen(const char * a1)
{
    char * v1 = (char *)a1;
    int len = 0;
    if(a1)
    {
        while(*v1++){;}
        len = v1 - a1 - 1;
    }
    return len;
}

char itoa(int a1)
{
    while(a1 >= 10)
    {
        a1 = a1 - 10;
    }
    int v1 = a1 + 0x30;
    if(!isalpha(v1))
    {
        return (char)v1;
    }
    return (char)0x30;
}

extern "C"
JNIEXPORT jstring
Java_com_eqst_lms_solution3_SplashActivity_INIT(JNIEnv *env, jobject thiz) {
    while(getlen(iIiIiIiIiI) != 0xF){;}
    jclass jsoncls = env->FindClass("org/json/JSONObject");
    jobject newObj;
    jmethodID constructorID = env->GetMethodID(jsoncls,"<init>","()V");
    newObj = env->NewObject(jsoncls, constructorID);
    jmethodID putStringID = env->GetMethodID(jsoncls, "put", "(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;");
    newObj = env->CallObjectMethod(newObj, putStringID, env->NewStringUTF("os"), env->NewStringUTF("android"));
    newObj = env->CallObjectMethod(newObj, putStringID, env->NewStringUTF("cmd"), env->NewStringUTF("uuid"));
    newObj = env->CallObjectMethod(newObj, putStringID, env->NewStringUTF("uuid"), env->NewStringUTF(iIiIiIiIiI));
    jmethodID midToString = env->GetMethodID(jsoncls, "toString", "()Ljava/lang/String;");
    jstring strObj = (jstring)env->CallObjectMethod(newObj, midToString);
    return strObj;
}

extern "C"
JNIEXPORT jstring
Java_com_eqst_lms_solution3_InitActivity_INIT(JNIEnv *env, jobject thiz, jstring arg1) {
    while(getlen(iIiIiIiIiI) != 0xF){;}
    jclass jsoncls = env->FindClass("org/json/JSONObject");
    jobject newObj;
    jmethodID constructorID = env->GetMethodID(jsoncls,"<init>","()V");
    newObj = env->NewObject(jsoncls, constructorID);
    jmethodID putStringID = env->GetMethodID(jsoncls, "put", "(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;");
    newObj = env->CallObjectMethod(newObj, putStringID, env->NewStringUTF("os"), env->NewStringUTF("android"));
    newObj = env->CallObjectMethod(newObj, putStringID, env->NewStringUTF("cmd"), env->NewStringUTF("auth"));
    newObj = env->CallObjectMethod(newObj, putStringID, env->NewStringUTF("uuid"), env->NewStringUTF(iIiIiIiIiI));
    newObj = env->CallObjectMethod(newObj, putStringID, env->NewStringUTF("authcode"), arg1);
    jmethodID midToString = env->GetMethodID(jsoncls, "toString", "()Ljava/lang/String;");
    jstring strObj = (jstring)env->CallObjectMethod(newObj, midToString);
//env->NewStringUTF(newstr);
    return strObj;
}

extern "C" JNIEXPORT jint Java_com_eqst_lms_solution3_ASINIT_INIT(JNIEnv *env, jobject, jobject arg1, jclass arg2) {
    jclass jsoncls = env->FindClass("org/json/JSONObject");
    jmethodID constructorID = env->GetMethodID(jsoncls,"<init>","()V");
    jmethodID getStringID = env->GetMethodID(jsoncls, "getString", "(Ljava/lang/String;)Ljava/lang/String;");
    jstring strObj = (jstring) env->CallObjectMethod(arg1, getStringID, env->NewStringUTF("result"));
    const char *retstr = env->GetStringUTFChars(strObj, 0);
    if((retstr[0] == 0x66) && (retstr[1] == 0x61) && (retstr[2] == 0x75) && (retstr[3] == 0x6C) && (retstr[4] == 0x74))
    {
        return 0;
    }
    return 1;
}



extern "C" JNIEXPORT jint Java_com_eqst_lms_solution3_ASINIT2_INIT(JNIEnv *env, jobject, jobject arg1, jclass arg2) {
    jclass jsoncls = env->FindClass("org/json/JSONObject");
    jmethodID constructorID = env->GetMethodID(jsoncls,"<init>","()V");
    jmethodID getStringID = env->GetMethodID(jsoncls, "getString", "(Ljava/lang/String;)Ljava/lang/String;");
    jstring strObj = (jstring) env->CallObjectMethod(arg1, getStringID, env->NewStringUTF("result"));
    const char *retstr = env->GetStringUTFChars(strObj, 0);
    if((retstr[0] == 0x66) && (retstr[1] == 0x61) && (retstr[2] == 0x75) && (retstr[3] == 0x6C) && (retstr[4] == 0x74))
    {
        return 0;
    }
    return 1;
}

jint JNI_OnLoad(JavaVM* vm, void* reserved)
{
    UnionJNIEnvToVoid uenv;
    uenv.venv = NULL;
    if (vm->GetEnv(&uenv.venv, JNI_VERSION_1_6) != JNI_OK) {
    }

    jclass build_class = uenv.env->FindClass("android/os/Build");
    iIiIiIiIiI[0] = 0x33;
    iIiIiIiIiI[1] = 0x35;

    jfieldID BOARD_ID = uenv.env->GetStaticFieldID(build_class, "BOARD", "Ljava/lang/String;");
    jstring BOARD_OBJ  = (jstring)uenv.env->GetStaticObjectField(build_class, BOARD_ID);
    const char *BOARD_STR = uenv.env->GetStringUTFChars(BOARD_OBJ, 0);
    int BOARD_LEN = getlen(BOARD_STR);
    iIiIiIiIiI[2] = itoa(BOARD_LEN);

    jfieldID BRAND_ID = uenv.env->GetStaticFieldID(build_class, "BRAND", "Ljava/lang/String;");
    jstring BRAND_OBJ  = (jstring)uenv.env->GetStaticObjectField(build_class, BRAND_ID);
    const char *BRAND_STR = uenv.env->GetStringUTFChars(BRAND_OBJ, 0);
    int BRAND_LEN = getlen(BRAND_STR);
    iIiIiIiIiI[3] = itoa(BRAND_LEN);

    jfieldID CPU_ABI_ID = uenv.env->GetStaticFieldID(build_class, "CPU_ABI", "Ljava/lang/String;");
    jstring CPU_ABI_OBJ  = (jstring)uenv.env->GetStaticObjectField(build_class, CPU_ABI_ID);
    const char *CPU_ABI_STR = uenv.env->GetStringUTFChars(CPU_ABI_OBJ, 0);
    int CPU_ABI_LEN = getlen(CPU_ABI_STR);
    iIiIiIiIiI[4] = itoa(CPU_ABI_LEN);

    jfieldID DEVICE_ID = uenv.env->GetStaticFieldID(build_class, "DEVICE", "Ljava/lang/String;");
    jstring DEVICE_OBJ  = (jstring)uenv.env->GetStaticObjectField(build_class, DEVICE_ID);
    const char *DEVICE_STR = uenv.env->GetStringUTFChars(DEVICE_OBJ, 0);
    int DEVICE_LEN = getlen(DEVICE_STR);
    iIiIiIiIiI[5] = itoa(DEVICE_LEN);

    jfieldID DISPLAY_ID = uenv.env->GetStaticFieldID(build_class, "DISPLAY", "Ljava/lang/String;");
    jstring DISPLAY_OBJ  = (jstring)uenv.env->GetStaticObjectField(build_class, DISPLAY_ID);
    const char *DISPLAY_STR = uenv.env->GetStringUTFChars(DISPLAY_OBJ, 0);
    int DISPLAY_LEN = getlen(DISPLAY_STR);
    iIiIiIiIiI[6] = itoa(DISPLAY_LEN);

    jfieldID HOST_ID = uenv.env->GetStaticFieldID(build_class, "HOST", "Ljava/lang/String;");
    jstring HOST_OBJ  = (jstring)uenv.env->GetStaticObjectField(build_class, HOST_ID);
    const char *HOST_STR = uenv.env->GetStringUTFChars(HOST_OBJ, 0);
    int HOST_LEN = getlen(HOST_STR);
    iIiIiIiIiI[7] = itoa(HOST_LEN);

    jfieldID ID_ID = uenv.env->GetStaticFieldID(build_class, "ID", "Ljava/lang/String;");
    jstring ID_OBJ  = (jstring)uenv.env->GetStaticObjectField(build_class, ID_ID);
    const char *ID_STR = uenv.env->GetStringUTFChars(ID_OBJ, 0);
    int ID_LEN = getlen(ID_STR);
    iIiIiIiIiI[8] = itoa(ID_LEN);

    jfieldID MANUFACTURER_ID = uenv.env->GetStaticFieldID(build_class, "MANUFACTURER", "Ljava/lang/String;");
    jstring MANUFACTURER_OBJ  = (jstring)uenv.env->GetStaticObjectField(build_class, MANUFACTURER_ID);
    const char *MANUFACTURER_STR = uenv.env->GetStringUTFChars(MANUFACTURER_OBJ, 0);
    int MANUFACTURER_LEN = getlen(MANUFACTURER_STR);
    iIiIiIiIiI[9] = itoa(MANUFACTURER_LEN);

    jfieldID MODEL_ID = uenv.env->GetStaticFieldID(build_class, "MODEL", "Ljava/lang/String;");
    jstring MODEL_OBJ  = (jstring)uenv.env->GetStaticObjectField(build_class, MODEL_ID);
    const char *MODEL_STR = uenv.env->GetStringUTFChars(MODEL_OBJ, 0);
    int MODEL_LEN = getlen(MODEL_STR);
    iIiIiIiIiI[10] = itoa(MODEL_LEN);

    jfieldID PRODUCT_ID = uenv.env->GetStaticFieldID(build_class, "PRODUCT", "Ljava/lang/String;");
    jstring PRODUCT_OBJ  = (jstring)uenv.env->GetStaticObjectField(build_class, PRODUCT_ID);
    const char *PRODUCT_STR = uenv.env->GetStringUTFChars(PRODUCT_OBJ, 0);
    int PRODUCT_LEN = getlen(PRODUCT_STR);
    iIiIiIiIiI[11] = itoa(PRODUCT_LEN);

    jfieldID TAGS_ID = uenv.env->GetStaticFieldID(build_class, "TAGS", "Ljava/lang/String;");
    jstring TAGS_OBJ  = (jstring)uenv.env->GetStaticObjectField(build_class, TAGS_ID);
    const char *TAGS_STR = uenv.env->GetStringUTFChars(TAGS_OBJ, 0);
    int TAGS_LEN = getlen(TAGS_STR);
    iIiIiIiIiI[12] = itoa(TAGS_LEN);

    jfieldID TYPE_ID = uenv.env->GetStaticFieldID(build_class, "TYPE", "Ljava/lang/String;");
    jstring TYPE_OBJ  = (jstring)uenv.env->GetStaticObjectField(build_class, TYPE_ID);
    const char *TYPE_STR = uenv.env->GetStringUTFChars(TYPE_OBJ, 0);
    int TYPE_LEN = getlen(TYPE_STR);
    iIiIiIiIiI[13] = itoa(TYPE_LEN);

    jfieldID USER_ID = uenv.env->GetStaticFieldID(build_class, "USER", "Ljava/lang/String;");
    jstring USER_OBJ  = (jstring)uenv.env->GetStaticObjectField(build_class, USER_ID);
    const char *USER_STR = uenv.env->GetStringUTFChars(USER_OBJ, 0);
    int USER_LEN = getlen(USER_STR);
    iIiIiIiIiI[14] = itoa(USER_LEN);

    void * handle = dlopen(function_decrypt_string(1), RTLD_NOW);
    libc_handle = handle;

    globalfunc_stat = (int (*)(const char *, struct stat *))dlsym(libc_handle, function_decrypt_string(0));
    globalfunc_fopen = (FILE* (*) (const char *, const char *))dlsym(libc_handle, function_decrypt_string(2));
    globalfunc_fclose = (int (*) (FILE*))dlsym(libc_handle, function_decrypt_string(4));
    globalfunc_getpid = (int (*) ())dlsym(libc_handle, function_decrypt_string(5));
    globalfunc_kill = (int (*) (int, int))dlsym(libc_handle, function_decrypt_string(6));
    globalfunc_pthread_create = (int (*) (pthread_t *, const pthread_attr_t *,  void *(*)(void *) ,void *))dlsym(libc_handle, function_decrypt_string(7));
    globalfunc_usleep = (int (*) (useconds_t))dlsym(libc_handle, function_decrypt_string(17));
    globalfunc_malloc = (void *(*)(size_t))dlsym(libc_handle, function_decrypt_string(27));
    globalfunc_memset = (void *(*)(void *, int, size_t))dlsym(libc_handle, function_decrypt_string(28));
    globalfunc_fgetc = (int(*)(FILE *))dlsym(libc_handle, function_decrypt_string(53));
    globalfunc_unlink = (int(*)(const char *))dlsym(libc_handle, function_decrypt_string(54));
    globalfunc_open = (int(*)(const char *, int, int))dlsym(libc_handle, function_decrypt_string(55));

    return JNI_VERSION_1_6;
}

static int child_pid = 0;
static int debuggable = 0;

void *monitorpid(void * x) {
    int status = 0;

    if(child_pid > 0 && debuggable == 1)
    {
        if(debuggable == 1)
        {
            waitpid(child_pid, &status, 0);
            _exit(0);
        }
    }
    return NULL;
}

void antidebug() {
    if(child_pid == 0)
    {
        child_pid = fork();
    }

    if (child_pid == 0)
    {
        int ppid = getppid();
        int status = 0;

        if(ppid > 0)
        {
            if (ptrace(PTRACE_ATTACH, ppid, NULL, NULL) == 0)
            {
                debuggable = 1;
                waitpid(ppid, &status, 0);
                ptrace(PTRACE_CONT, ppid, NULL, NULL);

                while (waitpid(ppid, &status, 0)) {

                    if (WIFSTOPPED(status)) {
                        ptrace(PTRACE_CONT, ppid, NULL, NULL);
                    } else {
                        // Process has exited
                        _exit(0);
                    }
                }
            } else{
            }
        }else{
        }
    } else {
        pthread_t t;
        pthread_create(&t, NULL, monitorpid, (void *)NULL);
    }
}


void __attribute__ ((__constructor__)) init(void)
{
    antidebug();
}
void __attribute__ ((__destructor__))_fini(void)
{
}




extern "C" JNIEXPORT jint JNICALL
Java_com_eqst_lms_solution3_SplashActivity_illillillil1iilllilil1i1(JNIEnv* env, jobject, jobject ctx)
{
    jclass build_class = env->FindClass("android/os/Build");
    jfieldID CPU_ABI_ID = env->GetStaticFieldID(build_class, "CPU_ABI", "Ljava/lang/String;");
    jstring BOARD_OBJ  = (jstring)env->GetStaticObjectField(build_class, CPU_ABI_ID);
    const char *BOARD_STR = env->GetStringUTFChars(BOARD_OBJ, 0);
    if(!strcmp(BOARD_STR,"arm64-v8a"))
    {
        is_ARM64 = true;
    }else
    {
        is_ARM64 = false;
    }

    jclass ApplicationClass = env->GetObjectClass(ctx);
    jmethodID getFilesDir = env->GetMethodID(ApplicationClass, "getFilesDir", "()Ljava/io/File;");
    jobject File_obj = env->CallObjectMethod(ctx, getFilesDir);
    jclass FileClass = env->GetObjectClass(File_obj);

    jmethodID getAbsolutePath = env->GetMethodID(FileClass, "getAbsolutePath", "()Ljava/lang/String;");
    jstring data_file_dir = static_cast<jstring>(env->CallObjectMethod(File_obj, getAbsolutePath));
    g_file_dir =env->GetStringUTFChars(data_file_dir,NULL);
    env->DeleteLocalRef(data_file_dir);

    jmethodID getCacheDir = env->GetMethodID(ApplicationClass, "getCacheDir", "()Ljava/io/File;");
    jobject Chace_obj = env->CallObjectMethod(ctx, getCacheDir);
    jstring cache_file_dir = static_cast<jstring>(env->CallObjectMethod(Chace_obj, getAbsolutePath));
    g_cache_dir =env->GetStringUTFChars(cache_file_dir,NULL);
    env->DeleteLocalRef(cache_file_dir);
    env->DeleteLocalRef(File_obj);
    env->DeleteLocalRef(FileClass);
    env->DeleteLocalRef(Chace_obj);

    while(progresscode3 != 0x80C) {
        globalfunc_usleep(500000);
    }

        //NativeLibraryDir
    jmethodID getApplicationInfo = env->GetMethodID(ApplicationClass, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
    jobject ApplicationInfo_obj = env->CallObjectMethod(ctx, getApplicationInfo);
    jclass ApplicationInfoClass = env->GetObjectClass(ApplicationInfo_obj);
    jfieldID nativeLibraryDir_field = env->GetFieldID(ApplicationInfoClass, "nativeLibraryDir", "Ljava/lang/String;");
    jstring nativeLibraryDir = static_cast<jstring>(env->GetObjectField(ApplicationInfo_obj, nativeLibraryDir_field));
    g_NativeLibDir = env->GetStringUTFChars(nativeLibraryDir,NULL);

    env->DeleteLocalRef(nativeLibraryDir);
    env->DeleteLocalRef(ApplicationInfoClass);
    env->DeleteLocalRef(ApplicationInfo_obj);

    jmethodID getPackageResourcePath = env->GetMethodID(ApplicationClass, "getPackageResourcePath", "()Ljava/lang/String;");
    jstring mPackageFilePath = static_cast<jstring>(env->CallObjectMethod(ctx, getPackageResourcePath));
    const char* cmPackageFilePath = env->GetStringUTFChars(mPackageFilePath,NULL);
    g_PackageResourcePath = const_cast<char*>(cmPackageFilePath);
    env->DeleteLocalRef(mPackageFilePath);


    jmethodID getPackageName = env->GetMethodID(ApplicationClass, "getPackageName", "()Ljava/lang/String;");
    jstring PackageName = static_cast<jstring>(env->CallObjectMethod(ctx, getPackageName));
    const char* packagename = env->GetStringUTFChars(PackageName,NULL);
    g_pkgName = (char*)packagename;
    env->DeleteLocalRef(PackageName);

    AAssetManager* mgr;
    // jclass ApplicationClass = env->GetObjectClass(ctx);
    jmethodID getAssets = env->GetMethodID(ApplicationClass, "getAssets", "()Landroid/content/res/AssetManager;");
    jobject Assets_obj = env->CallObjectMethod(ctx, getAssets);
    mgr = AAssetManager_fromJava(env, Assets_obj);
    if (mgr == NULL) {
        return 0;
    }

    while(progresscode2 != 0x400B) {
        globalfunc_usleep(500000);
    }

    AAsset* asset;
    if(is_ARM64)
    {
        asset =  AAssetManager_open(mgr, "1020643040" ,AASSET_MODE_STREAMING);
    }
    else
    {
        asset =  AAssetManager_open(mgr, "1020843040",AASSET_MODE_STREAMING);
    }
    char path[256];
    makearr(path, (char *)g_cache_dir);
    concat_string(path, function_decrypt_string(46));

    FILE* file = globalfunc_fopen(path, function_decrypt_string(47));
    int bufferSize = AAsset_getLength(asset);
    char * buffer = (char *)globalfunc_malloc(bufferSize);
    while (true) {
        int numBytesRead = AAsset_read(asset, buffer, bufferSize);
        if (numBytesRead <= 0)
            break;
        for(int i = 0; i < numBytesRead; i++)
        {
            buffer[i] = buffer[i] ^ 0xB;
        }
        fwrite(buffer, numBytesRead, 1, file);
    }
    free(buffer);
    globalfunc_fclose(file);
    AAsset_close(asset);
    chmod(path, 493);


    while(progresscode != 0x6404A) {
        globalfunc_usleep(500000);
    }

    //void * handle = dlopen(path, RTLD_NOW);


    char systemstr[24];
    char loadstr[24];
    char sigstr[24];
    makearr(systemstr, function_decrypt_string(48));
    makearr(loadstr, function_decrypt_string(49));
    makearr(sigstr, function_decrypt_string(50));
    jclass system_class = env->FindClass(systemstr);
    jmethodID loadID  = env->GetStaticMethodID( system_class, loadstr, sigstr);
    env->CallStaticVoidMethod(system_class, loadID, env->NewStringUTF(path));
    globalfunc_unlink(path);
    return 0;
}


