#include <Windows.h>

#ifndef __cplusplus
extern "C" {
#endif

#define NEAR_PATCH_SIZE 0x5
#define PROTECT_SIZE 0x6 //Longest instruction to check is FF15XXXXXXXX

PIMAGE_SECTION_HEADER get_section_addr_by_name(DWORD_PTR image_base, const char* section_name);
void replace_references(DWORD_PTR image_base, const char* section_name, LPVOID original_addr, LPVOID _hook_addr);
void patch_memory(LPVOID patch_addr, LPVOID replacement_addr);
int translate_exception(unsigned int code, struct _EXCEPTION_POINTERS *ep);

typedef int (__cdecl *pgenerate_number)(int a, int b);
pgenerate_number generate_number = (pgenerate_number)(0x00401000); //Example compiled to load at a fixed base address
//Otherwise an offset from an image/section base would be needed

int __cdecl generate_number_hook(int a, int b) {
    return 666;
}

int WINAPI MessageBoxA_hook(HWND hwnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    __asm pushad
    MessageBoxA(hwnd, "Hooked MessageBoxA called!", "MessageBoxA_hook", uType);
    __asm popad
    return MessageBoxA(hwnd, lpText, lpCaption, uType);
}

void replace_references(DWORD_PTR image_base, const char* section_name, LPVOID original_addr, LPVOID hook_addr) {
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)image_base;
    PIMAGE_SECTION_HEADER section_header = get_section_addr_by_name(image_base, section_name);
    BYTE* section_start = (BYTE*)(image_base + section_header->VirtualAddress);
    BYTE* section_end = section_start + section_header->SizeOfRawData;
    BYTE call_near_relative = 0xE8;
    BYTE call_near_absolute[] = {0xFF, 0x15}; 
    DWORD new_protections = PAGE_EXECUTE_READWRITE;
    DWORD old_protections = 0;
    for(section_start; section_start < section_end; ++section_start) {
        VirtualProtect(section_start, PROTECT_SIZE, new_protections, &old_protections);
        if(*section_start == call_near_relative) {
            BYTE offset[] = {
                *(section_start + 0x4),
                *(section_start + 0x3),
                *(section_start + 0x2),
                *(section_start + 0x1)
            };
            DWORD_PTR relative_offset = (((offset[0] & 0xFF) << 24) | ((offset[1] & 0xFF) << 16) | 
                ((offset[2] & 0xFF) << 8) | offset[3] & 0xFF) + NEAR_PATCH_SIZE;
            if((section_start + relative_offset) == original_addr) {
                DWORD_PTR hook_offset = (BYTE*)hook_addr - section_start - NEAR_PATCH_SIZE;                
                patch_memory((section_start + 0x1), &hook_offset);
            }
        }
        else if(memcmp(section_start, call_near_absolute, sizeof(call_near_absolute)) == 0) {
            BYTE offset[] = {
                *(section_start + 0x5),
                *(section_start + 0x4),
                *(section_start + 0x3),
                *(section_start + 0x2)
            };
            PDWORD_PTR absolute_addr = (PDWORD_PTR)(((offset[0] & 0xFF) << 24) | ((offset[1] & 0xFF) << 16) | 
                ((offset[2] & 0xFF) << 8) | offset[3] & 0xFF);
            __try {
                if(*absolute_addr == (DWORD_PTR)original_addr)
                    patch_memory(absolute_addr, &hook_addr);
            }
            __except(translate_exception(GetExceptionCode(), GetExceptionInformation())) {
                //Dereferenced bad pointer
            }
        }
        VirtualProtect(section_start, PROTECT_SIZE, old_protections, NULL);
    }
}

void patch_memory(LPVOID patch_addr, LPVOID replacement_addr) {
    DWORD old_protections = 0;
    VirtualProtect(patch_addr, sizeof(DWORD_PTR), PAGE_EXECUTE_READWRITE, &old_protections);
    memmove(patch_addr, replacement_addr, sizeof(DWORD_PTR));
    VirtualProtect(patch_addr, sizeof(DWORD_PTR), old_protections, NULL);
}

PIMAGE_SECTION_HEADER get_section_addr_by_name(DWORD_PTR image_base, const char* section_name) {
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)image_base;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)(image_base + dos_header->e_lfanew);
    for(int i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
        int section_offset = dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS) +
            (sizeof(IMAGE_SECTION_HEADER) * i);
        PIMAGE_SECTION_HEADER section_header = (PIMAGE_SECTION_HEADER)((BYTE*)image_base + section_offset);
        if(memcmp(section_header->Name, section_name, strlen(section_name)) == 0)
            return section_header;
    }
    return NULL;
}

int translate_exception(unsigned int code, struct _EXCEPTION_POINTERS *ep) {
    if (code == EXCEPTION_ACCESS_VIOLATION)
      return EXCEPTION_EXECUTE_HANDLER;
   else {
       MessageBox(NULL, L"Unexcepted exception raised!", L"Error", MB_ICONEXCLAMATION);
       return EXCEPTION_CONTINUE_SEARCH;
   }
} 

int APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID reserved) {
    if(dwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        DWORD_PTR image_base = (DWORD_PTR)GetModuleHandle(NULL);
        //Consider a new thread for actual use
        replace_references(image_base, ".text", &MessageBoxA, &MessageBoxA_hook);
        if(image_base == 0x00400000)
            replace_references(image_base, ".text", generate_number, &generate_number_hook);
        else
            MessageBox(NULL, L"Executable did not load at 0x00400000", L"Error", MB_ICONEXCLAMATION);
    }
    return TRUE;
}

#ifndef __cplusplus
}
#endif