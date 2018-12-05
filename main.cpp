

#define WIN32_LEAN_AND_MEAN
#define WIN32_EXTRA_LEAN
#include <windows.h>

#include "c:/libs/chromalib/crypto/Hash.hpp"

#include "module.hpp"

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <functional>

using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;

#define rcast reinterpret_cast
#define log(v) std::cout << v << std::endl;

bool loadFile(std::vector<u8>& data, const std::string& path)
{
    std::ifstream stream(path, std::ios::binary);

    if (stream.is_open())
    {
        stream.seekg(0, std::ios_base::end);
        data.resize(stream.tellg());
        stream.seekg(0, std::ios_base::beg);

        stream.read((char*)data.data(), data.size());
        stream.close();

        return true;
    }

    return false;
}

bool saveFile(const std::vector<u8>& data, const std::string& path)
{
    std::ofstream stream(path, std::ios::binary);

    if (stream.is_open())
    {
        stream.write((char*)data.data(), data.size());
        stream.close();

        return true;
    }

    return false;
}

static int alignAddress(int v, int a)
{
    if (v % a != 0)
        v += (a - v);

    return v;
}

bool buildNewHeader(const std::vector<u8>& data, std::vector<u8>& outputBuffer)
{
    struct Section
    {
        std::string name;
        IMAGE_SECTION_HEADER* ptr;
    };

    struct Export
    {
        std::string name;
        u32 virtualAddress;
        u32 rawAddress;
    };

    struct Import
    {
        u32 libHash;
        std::vector<u32> funcHashes;
    };

    struct Fixup
    {
        u32 sectionAddr;
        std::vector<u16> offsets;
    };

    std::vector<Section> sections;
    std::vector<Fixup> fixups;
    std::vector<Import> imports;
    std::vector<Export> exports;

    const auto rva2offset = [](DWORD rva, const IMAGE_SECTION_HEADER* const section)
    {
        return section->PointerToRawData + (rva - section->VirtualAddress);
    };

    // get pe headers
    auto* dataPtr = (u8*)data.data();
    const auto* dosHeader = rcast<IMAGE_DOS_HEADER*>(dataPtr);

    // not sure why this is offset by 1
    const auto ntHeader = rcast<IMAGE_NT_HEADERS32*>(dataPtr + dosHeader->e_lfanew);

    if (ntHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
    {
        log("Error: only 32 bit images are supported");
        return false;
    }

    // get section data
    auto* section = rcast<IMAGE_SECTION_HEADER*>(dataPtr + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32));
    const auto getSection = [=](const char* n)->IMAGE_SECTION_HEADER*
    {
        for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
        {
            if (strcmp(n, (const char*)section[i].Name) == 0)
                return &section[i];
        }

        return nullptr;
    };

    const auto* textSection = getSection(".text");
    const auto* rdataSection = getSection(".rdata");
    const auto* udataSection = getSection(".data");
    const auto* relocSection = getSection(".reloc");

    if (!textSection || !rdataSection || !relocSection)
    {
        log("Error: image does not contain a necessary section");
        return false;
    }

    if (udataSection)
        log("Info: Image contains uninitialised memory");

    // get exports data
    const auto exportsVA = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    const auto exportsAddr = rva2offset(exportsVA, rdataSection);
    const auto* exportHeader = rcast<IMAGE_EXPORT_DIRECTORY*>(dataPtr + exportsAddr);

    if (!exportsVA)
    {
        log("Error: image does export any functions");
        return false;
    }

    const auto* names = rcast<u32*>(dataPtr + rva2offset(exportHeader->AddressOfNames, rdataSection));
    const auto* funcs = rcast<u32*>(dataPtr + rva2offset(exportHeader->AddressOfFunctions, rdataSection));

    // get function pointers
    for (int i = 0; i < exportHeader->NumberOfFunctions; i++)
    {
        const auto* name = rcast<char*>(dataPtr + rva2offset(names[i], rdataSection));
        const auto funcAddr = rva2offset(funcs[i], textSection);

        exports.push_back({ name, 0, funcAddr });
    }

    // get imports
    const auto importsVA = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    const auto importsSize = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    const auto importsAddr = rva2offset(importsVA, rdataSection);
    auto* importHeader = rcast<IMAGE_IMPORT_DESCRIPTOR*>(dataPtr + importsAddr);

    if (!importsVA)
    {
        log("Warning: image does not import any external functions");
    }

    while (importHeader->Name)
    {
        IMAGE_THUNK_DATA32* thunk;

        const char* name = rcast<char*>(dataPtr + rva2offset(importHeader->Name, rdataSection));

        Import importedLib = { Hash::djb2Str(name) };

        if (importHeader->OriginalFirstThunk)
            thunk = rcast<IMAGE_THUNK_DATA32*>(dataPtr + rva2offset(importHeader->OriginalFirstThunk, rdataSection));
        else
            thunk = rcast<IMAGE_THUNK_DATA32*>(dataPtr + rva2offset(importHeader->FirstThunk, rdataSection));

        while (thunk->u1.AddressOfData)
        {
            const char* funcName = rcast<char*>(dataPtr + rva2offset(thunk->u1.AddressOfData + 2, rdataSection));

            importedLib.funcHashes.push_back(Hash::djb2Str(funcName));

            thunk++;
        }

        imports.push_back(importedLib);

        importHeader++;
    }

    // get relocation data
    const auto relocBlockHeaderSize = sizeof(DWORD) * 2;
    const auto relocVA = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    const auto relocSZ = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    const auto relocAddr = rva2offset(relocVA, relocSection);

    if (!relocVA)
    {
        log("Error: image does not contain relocation data");
        return false;
    }

    unsigned offset = 0;
    while (offset < relocSZ)
    {
        auto* relocHeader = rcast<IMAGE_RELOCATION*>(dataPtr + relocAddr + offset);

        const auto pageRVA = relocHeader->VirtualAddress;
        const auto itemCount = (relocHeader->SymbolTableIndex - relocBlockHeaderSize) / sizeof(u16);

        // the items are stored directly after the block
        const auto* items = rcast<u16*>(dataPtr + relocAddr + relocBlockHeaderSize);

        Fixup f = { pageRVA };

        for (int i = 0; i < itemCount; i++)
        {
            const auto item = items[i];

            const auto type = (item & 0xF000) >> 12;
            const auto addr = item & 0x0FFF;

            switch (type)
            {
            case 0x00: break;
            case 0x3: f.offsets.push_back(addr); break;
            default:
                break;
            }
        }

        fixups.push_back(f);

        offset += relocHeader->SymbolTableIndex;
    }

    const auto appendBlock = [](std::vector<u8>& vec, const u8* data, int size)->void
    {
        if (size)
        {
            auto offset = vec.size();
            vec.resize(vec.size() + size);
            memcpy(vec.data() + offset, data, size);
        }
    };

    // now we have all the data, build the tiny header

    std::vector<u8> moduleData;
    std::vector<u8> importBuffer;
    std::vector<u8> exportBuffer;
    std::vector<u8> fixupBuffer;

    ModuleHeader header = {};

    // fill header and copy code from code section
    header.code.va = (textSection->VirtualAddress & 0xF000) >> 12;
    header.code.offset = moduleData.size();
    header.code.size = textSection->Misc.VirtualSize;
    appendBlock(moduleData, dataPtr + textSection->PointerToRawData, header.code.size);
      
    // fill header and copy data from data section
    // debug section comes after the data section, we can use its address to calculate the actual size we need
    const auto dataSize = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress - rdataSection->VirtualAddress;
    header.data.va = (rdataSection->VirtualAddress & 0xF000) >> 12;
    header.data.offset = moduleData.size();
    header.data.size = dataSize;
    appendBlock(moduleData, dataPtr + rdataSection->PointerToRawData, header.data.size);

    // create udata section data
    if (udataSection)
    {
        header.udata.va = (udataSection->VirtualAddress & 0xF000) >> 12;
        header.udata.offset = 0;
        header.udata.size = udataSection->Misc.VirtualSize;
    }

    for (const auto& ex : exports)
    {
        const u32 nameHash = Hash::djb2Str(ex.name.c_str());
        const u32 addr = ex.rawAddress - textSection->PointerToRawData;

        appendBlock(exportBuffer, (u8*)&nameHash, sizeof(nameHash));
        appendBlock(exportBuffer, (u8*)&addr, sizeof(addr));
    }

    for (const auto& m : imports)
    {
        u32 moduleHash = m.libHash;
        u16 funcCount = m.funcHashes.size();

        appendBlock(importBuffer, (u8*)&moduleHash, sizeof(moduleHash));
        appendBlock(importBuffer, (u8*)&funcCount, sizeof(funcCount));

        for (u32 f : m.funcHashes)
        {
            appendBlock(importBuffer, (u8*)&f, sizeof(f));
        }
    }

    for (const auto& f : fixups)
    {
        u32 pageAddr = f.sectionAddr;
        u16 relocCount = f.offsets.size();

        appendBlock(fixupBuffer, (u8*)&pageAddr, sizeof(pageAddr));
        appendBlock(fixupBuffer, (u8*)&relocCount, sizeof(relocCount));

        for (auto relocOffset : f.offsets)
        {
            appendBlock(fixupBuffer, (u8*)&relocOffset, sizeof(relocOffset));
        }
    }

    header.sizeofExports = exportBuffer.size();
    header.sizeofImports = importBuffer.size();
    header.sizeofFixups = fixupBuffer.size();

    outputBuffer.clear();

    appendBlock(outputBuffer, (u8*)&header, sizeof(header));
    appendBlock(outputBuffer, (u8*)exportBuffer.data(), exportBuffer.size());
    appendBlock(outputBuffer, (u8*)importBuffer.data(), importBuffer.size());
    appendBlock(outputBuffer, (u8*)fixupBuffer.data(), fixupBuffer.size());
    appendBlock(outputBuffer, (u8*)moduleData.data(), moduleData.size());

    return true;
}

void __stdcall trampfunc()
{
    std::cout << "trampoline bitches" << std::endl;
}

LoadedModule* loadModule(void* location)
{
    static const u32 defaultAddress = 0x10000000;
    static const u32 requiredVirtualAlignment = 0x1000;

    auto* ptr = (u8*)location;
    auto* header = rcast<ModuleHeader*>(ptr);

    LoadedModule* module = new LoadedModule;

    do
    {
        static u32 address = defaultAddress;
        auto size = (header->code.va + header->data.va + header->udata.va) * 0x1000;
        module->addressSpace = (char*)VirtualAlloc((void*)address, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        address += requiredVirtualAlignment;
    } while (!module->addressSpace);

    const auto* dataPtr = ptr + sizeof(ModuleHeader) + header->sizeofExports + header->sizeofImports + header->sizeofFixups;

    // copy code, data and export data
    memcpy(module->addressSpace + (header->code.va * 0x1000), dataPtr + header->code.offset, header->code.size);
    memcpy(module->addressSpace + (header->data.va * 0x1000), dataPtr + header->data.offset, header->data.size);
    
    // zero out uninitialised data
    if (header->udata.size)
        memset(module->addressSpace + (header->udata.va * 0x1000), 0x00, header->udata.size);

    memcpy(module->addressSpace, ptr + sizeof(ModuleHeader), header->sizeofExports);

    module->numExports = header->sizeofExports / (sizeof(u32) * 2);
    module->exports = rcast<LoadedModule::Export*>(ptr + sizeof(ModuleHeader));

    // perform pointer fixups
    for (int i = 0; i < module->numExports; i++)
    {
        const auto addr = rcast<u32>(module->exports[i].ptr);
        module->exports[i].ptr = module->addressSpace + (header->code.va * 0x1000) + addr;

        log("pointer fixup: " << std::hex << module->exports[i].ptr);
    }

    // find imported functions
    auto* importData = rcast<char*>(ptr + sizeof(ModuleHeader) + header->sizeofExports);
    const auto importSize = header->sizeofImports;

    if (importSize)
    {
        u32 offset = 0;

        char* iatPtr = rcast<char*>(module->addressSpace + (header->data.va * 0x1000));
        u32 iatOffset = 0;

        while (offset < importSize)
        {
            const auto modHash = *rcast<u32*>(importData + offset); offset += 4;
            const auto numFuncs = *rcast<u16*>(importData + offset); offset += 2;

            for (int i = 0; i < numFuncs; i++)
            {
                auto funcNameHash = *rcast<u32*>(importData + offset); offset += 4;

                u32 trampAddress = rcast<u32>(trampfunc);
                memcpy(iatPtr + iatOffset, &trampAddress, 4);
                iatOffset += 4;
            }
        }
    }

    // perform relocations to code and data sections
    auto* relocData = rcast<char*>(ptr + sizeof(ModuleHeader) + header->sizeofExports + header->sizeofImports);
    const auto relocSize = header->sizeofFixups;

    const auto addressDelta = (u32)module->addressSpace - (u32)defaultAddress;
    if (addressDelta > 0)
    {
        size_t offset = 0;
        while (offset < relocSize)
        {
            const auto targetPage = *rcast<u32*>(relocData + offset); offset += 4;
            const auto numFixups = *rcast<u16*>(relocData + offset); offset += 2;

            u16* fixups = rcast<u16*>(relocData + offset);

            for (int i = 0; i < numFixups; i++)
            {
                auto addr = rcast<u32*>(module->addressSpace + targetPage + fixups[i]);
                *addr += addressDelta;

                offset += 2;
            }
        }
    }

    return module;
}

void unloadModule(LoadedModule* module)
{
    VirtualFree(module->addressSpace, 0, MEM_RELEASE);
    delete module;
}

// TODO: HANDLE .DATA SECTIONS WHEN THEY'RE NOT EMPTY

int main(int argc, const char** argv)
{
    std::vector<u8> packedData;
    std::vector<u8> fileData;

    //if (argc < 3)
    //    return -1;

    std::string input;// = argv[1];
    std::string output;// = argv[2];

    input = "C:\\Users\\oli\\Desktop\\dlltest\\main.dll";
    output = "C:\\Users\\oli\\Desktop\\dlltest\\main.module";

    if (loadFile(fileData, input))
    {
        if (!buildNewHeader(fileData, packedData))
            return-1;

        std::cout << "original size: \t" << fileData.size() << std::endl;
        std::cout << "packed size: \t" << packedData.size() << std::endl;
        std::cout << "delta: \t\t" << fileData.size() - packedData.size() << std::endl << std::endl;

        std::cout << "test loading..." << std::endl;
        auto module = loadModule(packedData.data());

        char buffer[512];

        rcast<bool(__stdcall*)(void*)>(module->exports[1].ptr)(buffer);
        rcast<bool(__stdcall*)(void*)>(module->exports[0].ptr)(buffer);

        unloadModule(module);
        std::cout << "looks good :)" << std::endl;

        saveFile(packedData, output);
    }

    return 0;
}