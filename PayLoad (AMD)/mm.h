#pragma once
#include "types.h"

#include <communication.hpp>

#define SELF_REF_PML4_IDX 510
#define MAPPING_PML4_IDX 100

#define MAPPING_ADDRESS_BASE 0x0000327FFFE00000
#define SELF_REF_PML4 0xFFFFFF7FBFDFE000

#define EPT_LARGE_PDPTE_OFFSET(_) (((u64)(_)) & ((0x1000 * 0x200 * 0x200) - 1))
#define EPT_LARGE_PDE_OFFSET(_) (((u64)(_)) & ((0x1000 * 0x200) - 1))

namespace mm
{
    enum class map_type_t
    {
        map_src,
        map_dest
    };

    typedef union _virt_addr_t
    {
        u64 value;
        struct
        {
            u64 offset_4kb : 12;
            u64 pt_index : 9;
            u64 pd_index : 9;
            u64 pdpt_index : 9;
            u64 pml4_index : 9;
            u64 reserved : 16;
        };

        struct
        {
            u64 offset_2mb : 21;
            u64 pd_index : 9;
            u64 pdpt_index : 9;
            u64 pml4_index : 9;
            u64 reserved : 16;
        };

        struct
        {
            u64 offset_1gb : 30;
            u64 pdpt_index : 9;
            u64 pml4_index : 9;
            u64 reserved : 16;
        };

    } virt_addr_t, * pvirt_addr_t;
    using phys_addr_t = virt_addr_t;

    typedef union _pml4e
    {
        u64 value;
        struct
        {
            u64 present : 1;          
            u64 writeable : 1;       
            u64 user_supervisor : 1;   
            u64 page_write_through : 1; 
            u64 page_cache : 1; 
            u64 accessed : 1;         
            u64 ignore_1 : 1;
            u64 page_size : 1;         
            u64 ignore_2 : 4;
            u64 pfn : 40; 
            u64 ignore_3 : 11;
            u64 nx : 1; 
        };
    } pml4e, * ppml4e;

    typedef union _pdpte
    {
        u64 value;
        struct
        {
            u64 present : 1;         
            u64 rw : 1;        
            u64 user_supervisor : 1;   
            u64 page_write_through : 1;
            u64 page_cache : 1; 
            u64 accessed : 1;         
            u64 ignore_1 : 1;
            u64 large_page : 1;        
            u64 ignore_2 : 4;
            u64 pfn : 40; 
            u64 ignore_3 : 11;
            u64 nx : 1; 
        };
    } pdpte, * ppdpte;

    typedef union _pde
    {
        u64 value;
        struct
        {
            u64 present : 1;          
            u64 rw : 1;       
            u64 user_supervisor : 1;  
            u64 page_write_through : 1;
            u64 page_cache : 1; 
            u64 accessed : 1;         
            u64 ignore_1 : 1;
            u64 large_page : 1;
            u64 ignore_2 : 4;
            u64 pfn : 40; 
            u64 ignore_3 : 11;
            u64 nx : 1; 
        };
    } pde, * ppde;

    typedef union _pte
    {
        u64 value;
        struct
        {
            u64 present : 1;          
            u64 rw : 1;       
            u64 user_supervisor : 1;   
            u64 page_write_through : 1;
            u64 page_cache : 1;
            u64 accessed : 1;         
            u64 dirty : 1;            
            u64 access_type : 1;   
            u64 global : 1;           
            u64 ignore_2 : 3;
            u64 pfn : 40;
            u64 ignore_3 : 7;
            u64 pk : 4;  
            u64 nx : 1; 
        };
    } pte, * ppte;

    typedef struct _npt_pml4e
    {
        union
        {
            u64 value;
            struct
            {
                u64 present : 1;
                u64 writeable : 1;
                u64 user : 1;
                u64 write_through : 1;
                u64 cache_disable : 1;
                u64 accessed : 1;
                u64 reserved1 : 3;
                u64 avl : 3;
                u64 pfn : 40;
                u64 reserved2 : 11;
                u64 nx : 1;
            };
        };
    } npt_pml4e, *pnpt_pml4e, npt_pdpte, 
      *pnpt_pdpte, npt_pde, *pnpt_pde;

    typedef struct _npt_pte
    {
        union
        {
            u64 value;
            struct
            {
                u64 present : 1;              
                u64 writeable : 1;            
                u64 user : 1;               
                u64 write_through : 1;       
                u64 cache_disable : 1;        
                u64 accessed : 1;            
                u64 dirty : 1;              
                u64 pat : 1;                
                u64 global : 1;             
                u64 avl : 3;                 
                u64 pfn : 40;   
                u64 reserved : 11;         
                u64 nx : 1;           
            };
        };
    } npt_pte, *pnpt_pte;

    typedef struct _npt_pde_2mb
    {
        union
        {
            u64 value;
            struct
            {
                u64 present : 1;
                u64 writeable : 1;
                u64 user : 1;
                u64 write_through : 1;
                u64 cache_disable : 1;
                u64 accessed : 1;
                u64 dirty : 1;
                u64 large_page : 1;
                u64 global : 1;
                u64 avl : 3;
                u64 pat : 1;
                u64 reserved1 : 8;
                u64 pfn : 31;
                u64 reserved2 : 11;
                u64 nx : 1;
            };
        };
    } npt_pde_2mb, * pnpt_pde_2mb;

    inline const ppml4e hyperv_pml4{ reinterpret_cast<ppml4e>(SELF_REF_PML4) };

    auto init() -> u64;
    auto map_guest_phys(guest_phys_t phys_addr, map_type_t map_type = map_type_t::map_src) -> u64;
    auto map_guest_virt(guest_phys_t dirbase, guest_virt_t virt_addr, map_type_t map_type = map_type_t::map_src) -> u64;

    auto map_page(host_phys_t phys_addr, map_type_t map_type = map_type_t::map_src) -> u64;

    auto translate(host_virt_t host_virt) -> u64;
    auto get_npte(guest_phys_t phys_addr) -> pnpt_pte;
    auto translate_guest_physical(guest_phys_t guest_phys, map_type_t map_type = map_type_t::map_src) -> u64;
    auto translate_guest_virtual(guest_phys_t dirbase, guest_virt_t guest_virt, map_type_t map_type = map_type_t::map_src) -> u64;

    auto read_guest_phys(guest_phys_t dirbase, guest_phys_t guest_phys, guest_virt_t guest_virt, u64 size) -> VMX_ROOT_ERROR;
    auto write_guest_phys(guest_phys_t dirbase, guest_phys_t guest_phys, guest_virt_t guest_virt, u64 size) -> VMX_ROOT_ERROR;
    auto copy_guest_virt(guest_phys_t dirbase_src, guest_virt_t virt_src, guest_virt_t dirbase_dest, guest_virt_t virt_dest, u64 size) -> VMX_ROOT_ERROR;
}