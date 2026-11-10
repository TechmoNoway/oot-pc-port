#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#include <stdlib.h>
#include <string.h>
#include "native_romfs.h"

#define ROMFS_INDEX_LIMIT (256u*1024u*1024u)
#define ROMFS_FILE_LIMIT UINT64_C(4294967296)
#define ROMFS_TOKEN_TAG UINT64_C(0x4f4f540000000000)
#define ROMFS_PATH_NOT_FOUND UINT64_C(0x202)
#define ROMFS_HANDLES 1024u
typedef struct RomFile {uint64_t token;uint32_t record,active;} RomFile;
struct OotRomFs {
    HANDLE source,cache;
    uint8_t *index,*records,*names,*verified;
    uint32_t count,directory_count;
    uint64_t name_bytes,serial;
    uint64_t guest_cache;
    uint8_t seal[32],mount_metadata[OOT_ROMFS_MOUNT_METADATA];
    char mount[16];
    RomFile handles[ROMFS_HANDLES];
    OotRomFsStats stats;
};
static uint32_t get32(const uint8_t *p){uint32_t v;memcpy(&v,p,4);return v;}
static uint64_t get64(const uint8_t *p){uint64_t v;memcpy(&v,p,8);return v;}
static void put64(uint8_t *p,uint64_t v){memcpy(p,&v,8);}
static int zero_bytes(const uint8_t *p,size_t size){for(size_t n=0;n<size;++n)if(p[n])return 0;return 1;}
static int utf8(const char *p,unsigned size){return size && MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,p,(int)size,NULL,0)>0;}
static wchar_t *wide_path(const char *path){
    size_t size=strlen(path);if(!size || size>32768)return NULL;
    int count=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,path,(int)size,NULL,0);
    if(!count)return NULL;
    wchar_t *wide=calloc((size_t)count+1,sizeof(*wide));if(!wide)return NULL;
    if(!MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,path,(int)size,wide,count)){free(wide);return NULL;}return wide;
}
static HANDLE open_read(const char *path){
    wchar_t *wide=wide_path(path);if(!wide)return INVALID_HANDLE_VALUE;
    HANDLE h=CreateFileW(wide,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_RANDOM_ACCESS,NULL);
    free(wide);
    if(h!=INVALID_HANDLE_VALUE){BY_HANDLE_FILE_INFORMATION info;
        if(!GetFileInformationByHandle(h,&info) || (info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))){CloseHandle(h);return INVALID_HANDLE_VALUE;}}
    return h;
}
static int file_size(HANDLE h,uint64_t *size){LARGE_INTEGER n;if(!GetFileSizeEx(h,&n)||n.QuadPart<0)return 0;*size=(uint64_t)n.QuadPart;return 1;}
static int read_at(HANDLE h,uint64_t offset,void *bytes,unsigned size){
    LARGE_INTEGER at;if(offset>INT64_MAX)return 0;at.QuadPart=(LONGLONG)offset;
    if(!SetFilePointerEx(h,at,NULL,FILE_BEGIN))return 0;
    unsigned done=0;while(done<size){DWORD got=0;
        if(!ReadFile(h,(uint8_t *)bytes+done,(DWORD)(size-done),&got,NULL)||!got)return 0;
        done+=got;
    }return 1;
}
static int sha(const uint8_t *bytes,unsigned size,uint8_t out[32]){
    BCRYPT_HASH_HANDLE h=NULL;int ok=0;
    if(BCryptCreateHash(BCRYPT_SHA256_ALG_HANDLE,&h,NULL,0,NULL,0,0)>=0){
        if(BCryptHashData(h,(PUCHAR)bytes,size,0)>=0 && BCryptFinishHash(h,out,32,0)>=0)ok=1;
        BCryptDestroyHash(h);
    }return ok;
}
static int canonical(const char *name,unsigned size){
    if(!utf8(name,size) || size>OOT_MEMORY_SERVICE_PATH_LIMIT)return 0;
    unsigned start=0;
    for(unsigned n=0;n<=size;++n){
        if(n<size && (name[n]=='\\'||name[n]==':'||!name[n]))return 0;
        if(n==size || name[n]=='/'){
            unsigned len=n-start;
            if(!len || (len==1&&name[start]=='.') || (len==2&&name[start]=='.'&&name[start+1]=='.'))return 0;
            start=n+1;
        }
    }return 1;
}
static int compare_name(const char *a,unsigned an,const char *b,unsigned bn){
    unsigned size=an<bn ? an:bn;int order=memcmp(a,b,size);
    return order ? order:an<bn ? -1:an>bn;
}
void oot_romfs_close(OotRomFs *fs){
    if(!fs)return;
    if(fs->source!=INVALID_HANDLE_VALUE)CloseHandle(fs->source);
    if(fs->cache!=INVALID_HANDLE_VALUE)CloseHandle(fs->cache);
    free(fs->verified);free(fs->index);free(fs);
}
OotRomFs *oot_romfs_open_index(const char *path,uint64_t program_id,const uint8_t expected_sha256[32]){
    HANDLE input=INVALID_HANDLE_VALUE;OotRomFs *fs=NULL;uint64_t size=0,source_size=0,cache_size=0;
    uint8_t header[160],digest[32],source_header[128],cache_header[64];char *source_path=NULL,*cache_path=NULL;
    if(!path || !program_id || !expected_sha256)return NULL;
    input=open_read(path);
    if(input==INVALID_HANDLE_VALUE || !file_size(input,&size) || size<160 || size>ROMFS_INDEX_LIMIT || !read_at(input,0,header,160))goto fail;
    if(memcmp(header,"OOTRFS1\0",8)||get32(header+8)!=1||get32(header+12)!=160||get64(header+16)!=size||get64(header+24)!=program_id||
       get32(header+52)!=64||get32(header+48)>1000000||get64(header+56)>128u*1024u*1024u||
       !get32(header+64)||get32(header+64)>32768||get32(header+68)!=10||get32(header+140)!=1||!zero_bytes(header+144,16))goto fail;
    uint64_t names_at=160u+(uint64_t)get32(header+64)+get32(header+68)+(uint64_t)get32(header+48)*64;
    if(names_at>size || get64(header+56)!=size-names_at || get32(header+136)>get32(header+48))goto fail;
    fs=calloc(1,sizeof(*fs));if(!fs)goto fail;fs->source=fs->cache=INVALID_HANDLE_VALUE;
    fs->index=malloc((size_t)size);fs->count=get32(header+48);fs->directory_count=get32(header+136);fs->name_bytes=get64(header+56);
    fs->verified=calloc(fs->count ? fs->count:1,1);
    if(!fs->index || !fs->verified || !read_at(input,0,fs->index,(unsigned)size) ||
       !sha(fs->index,(unsigned)size,digest)||memcmp(digest,expected_sha256,32)||
       !sha(fs->index+160,(unsigned)size-160,digest)||memcmp(digest,header+104,32))goto fail;
    unsigned source_len=get32(header+64);const uint8_t *body=fs->index+160;
    if(memchr(body,0,source_len)||memcmp(body+source_len,"romfs.data",10)||!utf8((const char *)body,source_len))goto fail;
    source_path=calloc((size_t)source_len+1,1);if(!source_path)goto fail;memcpy(source_path,body,source_len);
    const char *slash1=strrchr(path,'/'),*slash2=strrchr(path,'\\'),*slash=slash1;
    if(!slash || (slash2 && slash2>slash))slash=slash2;
    if(!slash)goto fail;
    size_t parent=(size_t)(slash-path)+1;
    if(parent>32768-10)goto fail;
    cache_path=calloc(parent+11,1);if(!cache_path)goto fail;memcpy(cache_path,path,parent);memcpy(cache_path+parent,"romfs.data",10);
    fs->source=open_read(source_path);fs->cache=open_read(cache_path);
    if(fs->source==INVALID_HANDLE_VALUE||fs->cache==INVALID_HANDLE_VALUE||!file_size(fs->source,&source_size)||!file_size(fs->cache,&cache_size)||
       source_size!=get64(header+32)||cache_size!=get64(header+40)||source_size<128||cache_size<64||
       !read_at(fs->source,0,source_header,128)||!sha(source_header,128,digest)||memcmp(digest,header+72,32)||
       memcmp(source_header,"NUP\1",4)||get64(source_header+64)!=source_size||
       !read_at(fs->cache,0,cache_header,64)||memcmp(cache_header,"OOTRFSD1",8)||memcmp(cache_header+8,header+72,32)||
       get64(cache_header+40)!=source_size||get64(cache_header+48)!=program_id||get64(cache_header+56))goto fail;
    fs->records=fs->index+160+source_len+10;fs->names=fs->index+names_at;
    uint64_t consumed=0;uint32_t directories=0;const char *previous=NULL;unsigned previous_len=0;
    for(uint32_t n=0;n<fs->count;++n){
        const uint8_t *r=fs->records+(size_t)n*64;uint64_t name=get64(r),length=get64(r+16),offset=get64(r+24);
        unsigned name_len=get32(r+8),kind=get32(r+12);
        if(name!=consumed || !name_len || name_len>fs->name_bytes-consumed || kind>2 || length>ROMFS_FILE_LIMIT)goto fail;
        const char *text=(const char *)fs->names+name;
        if(!canonical(text,name_len) || (previous && compare_name(previous,previous_len,text,name_len)>=0))goto fail;
        if(kind==2){if(length||offset||!zero_bytes(r+32,32))goto fail;++directories;}
        else{uint64_t backing=kind ? cache_size:source_size;
            if(offset>backing || length>backing-offset || (length && (offset%16 || offset<(kind ? 64:get64(source_header+56)))))goto fail;}
        previous=text;previous_len=name_len;consumed+=name_len;
    }
    if(consumed!=fs->name_bytes||directories!=fs->directory_count)goto fail;
    fs->stats.files=fs->count-directories;fs->stats.directories=directories;fs->stats.cache_bytes=cache_size;
    memcpy(fs->seal,expected_sha256,32);
    CloseHandle(input);free(source_path);free(cache_path);return fs;
fail:
    if(input!=INVALID_HANDLE_VALUE)CloseHandle(input);
    free(source_path);free(cache_path);oot_romfs_close(fs);return NULL;
}
int oot_romfs_stats(const OotRomFs *fs,OotRomFsStats *out){if(!fs||!out)return 0;*out=fs->stats;return 1;}
int oot_romfs_handler_valid(uint32_t id){return id>=OOT_ROMFS_QUERY_CACHE&&id<=OOT_ROMFS_READ_EXACT_OPTION;}
int oot_romfs_returns_value(uint32_t id){return oot_romfs_handler_valid(id)&&id!=OOT_ROMFS_UNMOUNT&&id!=OOT_ROMFS_CLOSE_FILE;}
static int lookup(const OotRomFs *fs,const char *name,unsigned length,uint32_t *found){
    uint32_t low=0,high=fs->count;
    while(low<high){uint32_t at=low+(high-low)/2;const uint8_t *r=fs->records+(size_t)at*64;
        int order=compare_name((const char *)fs->names+get64(r),get32(r+8),name,length);
        if(order<0)low=at+1;else high=at;
    }
    if(low==fs->count)return 0;
    const uint8_t *r=fs->records+(size_t)low*64;
    if(compare_name((const char *)fs->names+get64(r),get32(r+8),name,length))return 0;
    *found=low;return 1;
}
static RomFile *handle(OotRomFs *fs,uint64_t token){
    for(unsigned n=0;n<ROMFS_HANDLES;++n)if(fs->handles[n].active&&fs->handles[n].token==token)return fs->handles+n;
    return NULL;
}
static int verify_file(OotRomFs *fs,uint32_t index){
    if(fs->verified[index])return 1;
    const uint8_t *r=fs->records+(size_t)index*64;uint64_t length=get64(r+16),offset=get64(r+24),done=0;
    HANDLE input=get32(r+12) ? fs->cache:fs->source;BCRYPT_HASH_HANDLE hash=NULL;
    uint8_t *bytes=malloc(1024u*1024u),digest[32];int ok=0;
    if(!bytes || BCryptCreateHash(BCRYPT_SHA256_ALG_HANDLE,&hash,NULL,0,NULL,0,0)<0)goto done;
    while(done<length){unsigned chunk=length-done>1024u*1024u ? 1024u*1024u:(unsigned)(length-done);
        if(!read_at(input,offset+done,bytes,chunk)||BCryptHashData(hash,bytes,chunk,0)<0)goto done;
        done+=chunk;}
    if(BCryptFinishHash(hash,digest,32,0)<0||memcmp(digest,r+32,32)||fs->stats.verified_files==UINT64_MAX)goto done;
    fs->verified[index]=1;++fs->stats.verified_files;ok=1;
done:if(hash)BCryptDestroyHash(hash);free(bytes);return ok;
}
static int native_report(OotNativeReport *report,uint32_t id,int status){
    if(report)*report=(OotNativeReport){(uint32_t)status,id,status==2 ? OOT_NATIVE_BAD_INPUT:OOT_NATIVE_OK,0};
    return status;
}
static int overlaps_cache(const OotRomFs *fs,uint64_t address,unsigned size){
    if(!fs->guest_cache||!fs->stats.mounted||!size)return 0;
    return address<=fs->guest_cache ? fs->guest_cache-address<size:address-fs->guest_cache<OOT_ROMFS_MOUNT_METADATA;
}
static int record_output(OotRomFs *fs,OotGuestMemory *memory,uint64_t address,const uint8_t *data,unsigned size){
    return !overlaps_cache(fs,address,size)&&oot_memory_store_record(memory,address,data,size);
}
int oot_romfs_call(OotRomFs *fs,uint32_t id,OotArm64State *state,OotGuestMemory *memory,OotNativeReport *report){
    OotArm64State result;char path[OOT_MEMORY_SERVICE_PATH_LIMIT+1];unsigned length=0;uint32_t index=0;
    uint8_t record[8];int status=1;
    if(!fs||!state||!memory||!oot_romfs_handler_valid(id))return native_report(report,id,1);
    if(!state->pc||state->pc>=(UINT64_C(1)<<39)||state->pc%4||state->sp%16||state->x[30]<4||state->x[30]>=(UINT64_C(1)<<39)||state->x[30]%4||
       (state->nzcv&UINT32_C(0x0fffffff)))return native_report(report,id,2);
    result=*state;result.pc=state->x[30];
    if(fs->stats.mounted && fs->guest_cache){
        uint8_t expected[OOT_ROMFS_MOUNT_METADATA];
        if(!oot_memory_load_record(memory,fs->guest_cache,expected,sizeof(expected))||memcmp(expected,fs->mount_metadata,sizeof(expected)))return native_report(report,id,2);
    }
    if(id==OOT_ROMFS_QUERY_CACHE){
        put64(record,OOT_ROMFS_MOUNT_METADATA);if(!record_output(fs,memory,state->x[0],record,8))status=2;else{result.x[0]=0;status=0;}
    }else if(id==OOT_ROMFS_MOUNT || id==OOT_ROMFS_MOUNT_CACHE || id==OOT_ROMFS_UNMOUNT){
        if(!oot_memory_load_service_path(memory,state->x[0],path,sizeof(path),&length))return native_report(report,id,2);
        if(!length||length>=sizeof(fs->mount))return native_report(report,id,1);
        for(unsigned n=0;n<length;++n)if(!((path[n]>='a'&&path[n]<='z')||(path[n]>='A'&&path[n]<='Z')||(path[n]>='0'&&path[n]<='9')||path[n]=='_'))return native_report(report,id,1);
        if(id==OOT_ROMFS_UNMOUNT){
            if(!fs->stats.mounted||strcmp(path,fs->mount)||fs->stats.open_handles)return native_report(report,id,1);
            fs->stats.mounted=0;fs->mount[0]=0;fs->guest_cache=0;status=0;
        }else{
            if(fs->stats.mounted || fs->stats.mount_calls==UINT64_MAX || (id==OOT_ROMFS_MOUNT_CACHE &&
               (state->x[2]<OOT_ROMFS_MOUNT_METADATA || state->x[2]>OOT_MEMORY_SERVICE_WRITE_LIMIT)))return native_report(report,id,1);
            uint8_t ticket[OOT_ROMFS_MOUNT_METADATA]={0},old[OOT_ROMFS_MOUNT_METADATA];
            memcpy(ticket,"OOTMNT1\0",8);memcpy(ticket+8,fs->seal,32);put64(ticket+40,fs->stats.mount_calls+1);memcpy(ticket+48,path,length+1);
            if(id==OOT_ROMFS_MOUNT_CACHE && (!oot_memory_load_record(memory,state->x[1],old,sizeof(old))||
               !oot_memory_store_record(memory,state->x[1],ticket,sizeof(ticket))))return native_report(report,id,2);
            memcpy(fs->mount_metadata,ticket,sizeof(ticket));fs->guest_cache=id==OOT_ROMFS_MOUNT_CACHE ? state->x[1]:0;
            memcpy(fs->mount,path,length+1);fs->stats.mounted=1;++fs->stats.mount_calls;result.x[0]=0;status=0;
        }
    }else if(id==OOT_ROMFS_OPEN_FILE || id==OOT_ROMFS_ENTRY_TYPE){
        if(!fs->stats.mounted || (id==OOT_ROMFS_OPEN_FILE && (uint32_t)state->x[2]!=1))return native_report(report,id,1);
        if(!oot_memory_load_service_path(memory,state->x[1],path,sizeof(path),&length))return native_report(report,id,2);
        unsigned prefix=(unsigned)strlen(fs->mount);
        if(length<prefix+2||memcmp(path,fs->mount,prefix)||path[prefix]!=':'||path[prefix+1]!='/')return native_report(report,id,1);
        const char *name=path+prefix+2;unsigned name_len=length-prefix-2;
        if(name_len && !canonical(name,name_len))return native_report(report,id,1);
        int found=name_len ? lookup(fs,name,name_len,&index):0;
        if(!name_len && id==OOT_ROMFS_OPEN_FILE)return native_report(report,id,1);
        if(!name_len && id==OOT_ROMFS_ENTRY_TYPE){memset(record,0,4);if(!record_output(fs,memory,state->x[0],record,4))return native_report(report,id,2);result.x[0]=0;status=0;}
        else if(!found){
            if(fs->stats.missing_paths==UINT64_MAX)return native_report(report,id,2);
            ++fs->stats.missing_paths;result.x[0]=ROMFS_PATH_NOT_FOUND;status=0;
        }else if(id==OOT_ROMFS_ENTRY_TYPE){
            memset(record,0,4);record[0]=get32(fs->records+(size_t)index*64+12)==2 ? 0:1;
            if(!record_output(fs,memory,state->x[0],record,4))return native_report(report,id,2);
            result.x[0]=0;status=0;
        }else{
            if(get32(fs->records+(size_t)index*64+12)==2 || fs->stats.open_calls==UINT64_MAX || fs->serial>=UINT32_MAX)return native_report(report,id,1);
            RomFile *slot=NULL;for(unsigned n=0;n<ROMFS_HANDLES;++n)if(!fs->handles[n].active){slot=fs->handles+n;break;}
            if(!slot)return native_report(report,id,1);
            if(overlaps_cache(fs,state->x[0],8)||!oot_memory_probe(memory,state->x[0],8,OOT_MEMORY_WRITE))return native_report(report,id,2);
            if(!verify_file(fs,index))return native_report(report,id,2);
            uint64_t token=ROMFS_TOKEN_TAG|(fs->serial+1);put64(record,token);
            if(!record_output(fs,memory,state->x[0],record,8))return native_report(report,id,2);
            *slot=(RomFile){token,index,1};++fs->serial;++fs->stats.open_calls;++fs->stats.open_handles;result.x[0]=0;status=0;
        }
    }else if(id==OOT_ROMFS_CLOSE_FILE){
        RomFile *file=handle(fs,state->x[0]);if(!file)return native_report(report,id,1);
        file->active=0;--fs->stats.open_handles;status=0;
    }else if(id==OOT_ROMFS_FILE_SIZE){
        RomFile *file=handle(fs,state->x[1]);if(!file)return native_report(report,id,1);
        put64(record,get64(fs->records+(size_t)file->record*64+16));
        if(!record_output(fs,memory,state->x[0],record,8))return native_report(report,id,2);
        result.x[0]=0;status=0;
    }else{
        unsigned counted=id==OOT_ROMFS_READ_COUNT||id==OOT_ROMFS_READ_COUNT_OPTION;
        unsigned option=id==OOT_ROMFS_READ_COUNT_OPTION||id==OOT_ROMFS_READ_EXACT_OPTION;
        unsigned base=counted ? 1:0;RomFile *file=handle(fs,state->x[base]);
        if(!file)return native_report(report,id,1);
        uint64_t offset=state->x[base+1],destination=state->x[base+2],size=state->x[base+3];
        if(offset>INT64_MAX||size>OOT_MEMORY_SERVICE_WRITE_LIMIT)return native_report(report,id,1);
        if(option){uint8_t flags[4];if(!oot_memory_load_record(memory,state->x[base+4],flags,4))return native_report(report,id,2);
            if(get32(flags))return native_report(report,id,1);}
        const uint8_t *r=fs->records+(size_t)file->record*64;uint64_t length_bytes=get64(r+16);
        if(offset>length_bytes || (!counted && size>length_bytes-offset))return native_report(report,id,1);
        if(size>length_bytes-offset)size=length_bytes-offset;
        if(fs->stats.read_calls==UINT64_MAX || size>UINT64_MAX-fs->stats.bytes_read)return native_report(report,id,2);
        uint8_t *data=size ? malloc((size_t)size):NULL;
        if(size && (!data||!read_at(get32(r+12) ? fs->cache:fs->source,get64(r+24)+offset,data,(unsigned)size))){free(data);return native_report(report,id,2);}
        OotServiceWrite writes[2];unsigned count=0;
        if(size)writes[count++]=(OotServiceWrite){destination,data,(uint32_t)size};
        if(counted){put64(record,size);writes[count++]=(OotServiceWrite){state->x[0],record,8};}
        for(unsigned n=0;n<count;++n)if(overlaps_cache(fs,writes[n].address,writes[n].size)){free(data);return native_report(report,id,2);}
        if(count && !oot_memory_store_service(memory,writes,count)){free(data);return native_report(report,id,2);}
        free(data);++fs->stats.read_calls;fs->stats.bytes_read+=size;result.x[0]=0;status=0;
    }
    if(!status)*state=result;
    return native_report(report,id,status);
}
