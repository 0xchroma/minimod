#pragma once

#include <cstdint>

using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;

struct ModuleHeader
{
    struct Section
    {
        u8 va;
        u16 offset;
        u16 size;
    };

    // offsets into the data for data and code sections
    Section code;
    Section data;
    Section udata;

    // the size of the buffers that immediatly follow the header
    u16 sizeofExports;
    u16 sizeofImports;
    u16 sizeofFixups;
};

struct LoadedModule
{
    struct Export { u32 hash; void* ptr; };
    char* addressSpace;
    int numExports;
    Export* exports;
};

struct ModuleRuntime
{
    int numModules;
    LoadedModule* modules;
};