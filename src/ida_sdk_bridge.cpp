#include <auto.hpp>
#include <bytes.hpp>
#include <diskio.hpp>
#include <funcs.hpp>
#include <loader.hpp>
#include <nalt.hpp>
#include <xref.hpp>
#include <offset.hpp>
#include <typeinf.hpp>
#include <ua.hpp>
#include <hexrays.hpp>
#include <algorithm>
#include <cstring>
#if defined(__linux__) || defined(__APPLE__)
#include <dlfcn.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

#if defined(__linux__) || defined(__APPLE__) || defined(_WIN32)
// The sdk-9.2 idalib wrapper passes "-B" to init_library(). IDA 9.2
// initializes successfully but returns 2 (the argument count), which that
// wrapper mistakes for an error. Normalize the call to the documented
// zero-argument form while preserving idalib's own once/mutex bookkeeping.
extern "C" int init_library(int, char *[]) {
  using init_library_fn = int (*)(int, char *[]);
#if defined(_WIN32)
  static auto real_init_library = [] {
    HMODULE module = GetModuleHandleW(L"idalib.dll");
    return module == nullptr
        ? static_cast<init_library_fn>(nullptr)
        : reinterpret_cast<init_library_fn>(
              GetProcAddress(module, "init_library"));
  }();
#else
  static auto real_init_library = reinterpret_cast<init_library_fn>(
      dlsym(RTLD_NEXT, "init_library"));
#endif
  return real_init_library == nullptr
      ? -1
      : real_init_library(0, nullptr);
}
#endif

extern "C" {

bool ida_mcp_save_database(const char *path, bool compress) {
  const char *destination = path != nullptr && path[0] != '\0' ? path : nullptr;
  return save_database(destination, compress ? DBFL_COMP : 0);
}

bool ida_mcp_add_func(uint64 start, uint64 end) {
  return add_func(ea_t(start), end == 0 ? BADADDR : ea_t(end));
}

int ida_mcp_create_insn(uint64 address) {
  return create_insn(ea_t(address));
}

bool ida_mcp_undefine(uint64 address, uint64 size) {
  return size != 0 && del_items(ea_t(address), DELIT_EXPAND, asize_t(size));
}

bool ida_mcp_reanalyze(uint64 start, uint64 end) {
  return end > start && plan_and_wait(ea_t(start), ea_t(end), true) != 0;
}

bool ida_mcp_make_data(
    uint64 address,
    const char *declaration,
    bool delete_existing,
    uint64 *out_size) {
  if (declaration == nullptr || declaration[0] == '\0' || out_size == nullptr)
    return false;
  if (!apply_cdecl(get_idati(), ea_t(address), declaration))
    return false;

  tinfo_t type;
  if (!get_tinfo(&type, ea_t(address)))
    return false;
  asize_t size = type.get_size();
  if (size == BADSIZE || size == 0)
    return false;

  if (delete_existing) {
    if (!del_items(ea_t(address), DELIT_EXPAND, size))
      return false;
    if (!create_byte(ea_t(address), size, true))
      return false;
    if (!apply_cdecl(get_idati(), ea_t(address), declaration))
      return false;
  }
  *out_size = uint64(size);
  return true;
}

bool ida_mcp_mark_cfunc_dirty(uint64 address) {
  return init_hexrays_plugin() && mark_cfunc_dirty(ea_t(address), false);
}

bool ida_mcp_init_hexrays() {
  return init_hexrays_plugin();
}

// The directory IDA resolves its own resource tree from — plugins, processor
// modules, loaders, cfg. It is *not* necessarily the directory this process
// loaded libida from: the linker honours RUNPATH, IDA honours $IDADIR, and the
// two disagreeing is the whole reason `crate::ida::install` exists.
//
// Only `idadir(nullptr)` is bridged, not `get_ida_subdirs`. The user-plugin
// search path ($IDAUSR/plugins) never holds the Hex-Rays modules, so appending
// "plugins" to this answers the only question we ask of it.
bool ida_mcp_idadir(char *buf, size_t buf_size) {
  if (buf == nullptr || buf_size == 0)
    return false;
  const char *dir = idadir(nullptr);
  if (dir == nullptr || dir[0] == '\0')
    return false;
  const size_t len = std::strlen(dir);
  if (len + 1 > buf_size)
    return false;
  std::memcpy(buf, dir, len + 1);
  return true;
}

int ida_mcp_enum_upsert_member(
    const char *enum_name,
    const char *member_name,
    uint64 value,
    bool bitfield,
    bool *created_enum,
    uint32 *ordinal) {
  if (enum_name == nullptr || enum_name[0] == '\0'
      || member_name == nullptr || member_name[0] == '\0'
      || created_enum == nullptr || ordinal == nullptr)
    return TERR_BAD_ARG;

  til_t *types = get_idati();
  tinfo_t type;
  *created_enum = false;
  if (!type.get_named_type(types, enum_name)) {
    if (!type.create_enum())
      return TERR_BAD_TYPE;
    if (bitfield && type.set_enum_is_bitmask(tinfo_t::ENUMBM_ON) != TERR_OK)
      return TERR_BAD_BF;
    if (type.set_named_type(types, enum_name, NTF_TYPE) != TERR_OK)
      return TERR_SAVE_ERROR;
    *created_enum = true;
    if (!type.get_named_type(types, enum_name))
      return TERR_BAD_TYPE;
  }
  if (!type.is_enum())
    return TERR_BAD_TYPE;
  if (type.is_bitmask_enum() != bitfield)
    return TERR_BAD_BF;

  *ordinal = type.get_ordinal();
  edm_t existing;
  if (type.get_edm(&existing, member_name) >= 0)
    return existing.value == value ? 2 : TERR_DUPNAME;
  if (type.get_edm_by_value(&existing, value) >= 0)
    return TERR_BAD_VALUE;

  tinfo_code_t code = type.add_edm(member_name, value);
  return code == TERR_OK ? 1 : int(code);
}

bool ida_mcp_rename_local(
    uint64 function_address,
    const char *old_name,
    const char *new_name) {
  return old_name != nullptr
      && new_name != nullptr
      && init_hexrays_plugin()
      && rename_lvar(ea_t(function_address), old_name, new_name);
}

bool ida_mcp_rename_stack(
    uint64 function_address,
    const char *old_name,
    const char *new_name) {
  if (old_name == nullptr || new_name == nullptr)
    return false;
  func_t *function = get_func(ea_t(function_address));
  if (function == nullptr)
    return false;
  tinfo_t frame;
  if (!tinfo_get_func_frame(&frame, function))
    return false;
  udm_t member;
  int index = frame.get_udm(&member, old_name);
  return index >= 0 && frame.rename_udm(size_t(index), new_name) == TERR_OK;
}

bool ida_mcp_get_applied_udt_name(
    uint64 address,
    char *buffer,
    size_t buffer_size) {
  if (buffer == nullptr || buffer_size == 0)
    return false;
  tinfo_t type;
  qstring name;
  if (!get_tinfo(&type, ea_t(address))
      || !type.is_udt()
      || !type.get_type_name(&name)
      || name.empty())
    return false;
  qstrncpy(buffer, name.c_str(), buffer_size);
  return true;
}

bool ida_mcp_operand_mask(
    uint64 address,
    uint64 size,
    unsigned char *mask) {
  if (size == 0 || mask == nullptr)
    return false;
  std::memset(mask, 1, size_t(size));
  ea_t start = ea_t(address);
  ea_t end = start + asize_t(size);
  for (ea_t current = start; current < end;) {
    insn_t instruction;
    int length = decode_insn(&instruction, current);
    if (length <= 0) {
      ++current;
      continue;
    }
    int bounded_length = int(std::min<asize_t>(asize_t(length), end - current));
    for (int index = 0; index < UA_MAXOP; ++index) {
      const op_t &operand = instruction.ops[index];
      if (operand.type == o_void)
        break;
      bool variable = operand.type == o_imm
          || operand.type == o_mem
          || operand.type == o_near
          || operand.type == o_far
          || operand.type == o_displ;
      if (!variable || operand.offb == 0 || operand.offb >= bounded_length)
        continue;
      int operand_end = bounded_length;
      for (int next = index + 1; next < UA_MAXOP; ++next) {
        const op_t &next_operand = instruction.ops[next];
        if (next_operand.type == o_void)
          break;
        if (next_operand.offb > operand.offb) {
          operand_end = std::min<int>(operand_end, next_operand.offb);
          break;
        }
      }
      size_t begin = size_t(current - start) + operand.offb;
      size_t finish = std::min<size_t>(
          size_t(current - start) + size_t(operand_end),
          size_t(size));
      std::memset(mask + begin, 0, finish - begin);
    }
    current += asize_t(length);
  }
  return true;
}

bool ida_mcp_set_operand_type(
    uint64 address,
    int operand,
    const char *kind,
    uint64 target,
    const char *struct_name,
    int64 delta) {
  if (kind == nullptr)
    return false;

  if (std::strcmp(kind, "offset") == 0)
    return op_plain_offset(ea_t(address), operand, ea_t(target));
  if (std::strcmp(kind, "stkvar") == 0)
    return op_stkvar(ea_t(address), operand);
  if (std::strcmp(kind, "hex") == 0)
    return op_hex(ea_t(address), operand);
  if (std::strcmp(kind, "dec") == 0)
    return op_dec(ea_t(address), operand);
  if (std::strcmp(kind, "char") == 0)
    return op_chr(ea_t(address), operand);
  if (std::strcmp(kind, "binary") == 0)
    return op_bin(ea_t(address), operand);
  if (std::strcmp(kind, "octal") == 0)
    return op_oct(ea_t(address), operand);
  if (std::strcmp(kind, "stroff") != 0 || struct_name == nullptr || struct_name[0] == '\0')
    return false;

  tinfo_t type;
  if (!type.get_named_type(get_idati(), struct_name))
    return false;
  tid_t path[] = {type.get_tid()};
  if (path[0] == BADNODE)
    return false;
  insn_t instruction;
  if (decode_insn(&instruction, ea_t(address)) <= 0)
    return false;
  return op_stroff(instruction, operand, path, 1, adiff_t(delta));
}

}
