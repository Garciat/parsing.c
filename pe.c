#include <assert.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define ALWAYS_INLINE __attribute__((always_inline))

// ==============================================================

const auto ENDIAN_LE = (int){0};
const auto ENDIAN_BE = (int){1};

uint16_t read_u2_le(const uint8_t* data) {
  return (uint16_t)(data[0] | (data[1] << 8));
}

uint16_t read_u2_be(const uint8_t* data) {
  return (uint16_t)((data[0] << 8) | data[1]);
}

uint16_t read_u2(const uint8_t* data, int endian) {
  return endian == ENDIAN_LE ? read_u2_le(data) : read_u2_be(data);
}

uint32_t read_u4_le(const uint8_t* data) {
  return (uint32_t)(data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24));
}

uint32_t read_u4_be(const uint8_t* data) {
  return (uint32_t)((data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]);
}

uint32_t read_u4(const uint8_t* data, int endian) {
  return endian == ENDIAN_LE ? read_u4_le(data) : read_u4_be(data);
}

uint64_t read_u8_le(const uint8_t* data) {
  return (uint64_t)(data[0] | ((uint64_t)data[1] << 8) | ((uint64_t)data[2] << 16) |
  ((uint64_t)data[3] << 24) | ((uint64_t)data[4] << 32) | ((uint64_t)data[5] << 40) |
  ((uint64_t)data[6] << 48) | ((uint64_t)data[7] << 56));
}

uint64_t read_u8_be(const uint8_t* data) {
  return (uint64_t)(((uint64_t)data[0] << 56) | ((uint64_t)data[1] << 48) |
  ((uint64_t)data[2] << 40) | ((uint64_t)data[3] << 32) | ((uint64_t)data[4] << 24) |
  ((uint64_t)data[5] << 16) | ((uint64_t)data[6] << 8) | (uint64_t)data[7]);
}

uint64_t read_u8(const uint8_t* data, int endian) {
  return endian == ENDIAN_LE ? read_u8_le(data) : read_u8_be(data);
}

// ==============================================================

typedef struct Parser {
  enum {
    // Primitive parsers
    PARSER_SKIP,
    PARSER_U2,
    PARSER_U4,
    PARSER_U8,

    // Composite parsers
    PARSER_CAPTURE,
    PARSER_CONST,
    PARSER_SEQ,
    PARSER_ALT,
  } kind;
  union {
    struct { size_t count; } skip;
    struct { int endian; } u2;
    struct { int endian; } u4;
    struct { int endian; } u8;
    struct {
      struct Parser *parser;
      void *output;
    } capture;
    struct {
      struct Parser *parser;
      union {
        uint16_t u2;
        uint32_t u4;
        uint64_t u8;
      };
    } constant;
    struct { struct Parser **parsers; } seq;
    struct { struct Parser **parsers; } alt;
  };
} Parser;

#define U2_LE() (&(Parser){ .kind = PARSER_U2, .u2 = { .endian = ENDIAN_LE } })
#define U2_BE() (&(Parser){ .kind = PARSER_U2, .u2 = { .endian = ENDIAN_BE } })
#define U4_LE() (&(Parser){ .kind = PARSER_U4, .u4 = { .endian = ENDIAN_LE } })
#define U4_BE() (&(Parser){ .kind = PARSER_U4, .u4 = { .endian = ENDIAN_BE } })
#define U8_LE() (&(Parser){ .kind = PARSER_U8, .u8 = { .endian = ENDIAN_LE } })
#define U8_BE() (&(Parser){ .kind = PARSER_U8, .u8 = { .endian = ENDIAN_BE } })

#define SKIP(n) (&(Parser){ .kind = PARSER_SKIP, .skip = { .count = n } })

#define CAPTURE(o, p) (&(Parser){ .kind = PARSER_CAPTURE, .capture = { .parser = p, .output = o } })

#define CONST_U2(value, p) (&(Parser){ .kind = PARSER_CONST, .constant = { .u2 = value, .parser = p } })
#define CONST_U4(value, p) (&(Parser){ .kind = PARSER_CONST, .constant = { .u4 = value, .parser = p } })
#define CONST_U8(value, p) (&(Parser){ .kind = PARSER_CONST, .constant = { .u8 = value, .parser = p } })

#define SEQ(...) (&(Parser){ .kind = PARSER_SEQ, .seq = { (Parser*[]){ __VA_ARGS__, nullptr } } })
#define ALT(...) (&(Parser){ .kind = PARSER_ALT, .alt = { (Parser*[]){ __VA_ARGS__, nullptr } } })

// ==============================================================

typedef struct ParserState {
  uint8_t* data;
  size_t count;
  size_t offset;
} ParserState;

ALWAYS_INLINE
bool state_has_bytes(ParserState state, size_t count) {
  return state.offset + count <= state.count;
}

ALWAYS_INLINE
const uint8_t *state_current(ParserState state) {
  assert(state.offset < state.count);
  return state.data + state.offset;
}

ALWAYS_INLINE
ParserState state_advance(ParserState state, size_t count) {
  assert(state_has_bytes(state, count));
  return (ParserState){ .data = state.data, .count = state.count, .offset = state.offset + count };
}

typedef struct ParserResult {
  enum {
    RESULT_CONSUMED_OK,
    RESULT_EMPTY_OK,
    RESULT_CONSUMED_ERROR,
    RESULT_EMPTY_ERROR,
  } kind;
  ParserState state;
  union {
    struct { Parser *expected; } error;
    struct {
      enum {
        RESULT_U2,
        RESULT_U4,
        RESULT_U8,
      } kind;
      union {
        uint16_t u2;
        uint32_t u4;
        uint64_t u8;
      };
    } ok;
  };
} ParserResult;

ALWAYS_INLINE
ParserResult result_fail_empty(ParserState state, Parser *expected) {
  return (ParserResult){
    .kind = RESULT_EMPTY_ERROR,
    .state = state,
    .error = { .expected = expected }
  };
}

ALWAYS_INLINE
ParserResult result_fail_consumed(ParserState state, Parser *expected) {
  return (ParserResult){
    .kind = RESULT_CONSUMED_ERROR,
    .state = state,
    .error = { .expected = expected }
  };
}

// ==============================================================

ALWAYS_INLINE
ParserResult parse_rec(ParserState state, Parser *parser);

ALWAYS_INLINE
ParserResult parser_run(ParserState state, Parser *parser) {
  return parse_rec(state, parser);
}

ALWAYS_INLINE
ParserResult parse_skip(ParserState state, Parser *parser) {
  assert(parser->kind == PARSER_SKIP);

  if (!state_has_bytes(state, parser->skip.count)) {
    return result_fail_empty(state, parser);
  }

  return (ParserResult){
    .kind = RESULT_CONSUMED_OK,
    .state = state_advance(state, parser->skip.count)
  };
}

ALWAYS_INLINE
ParserResult parse_u2(ParserState state, Parser *parser) {
  assert(parser->kind == PARSER_U2);

  if (!state_has_bytes(state, 2)) {
    return result_fail_empty(state, parser);
  }

  return (ParserResult){
    .kind = RESULT_CONSUMED_OK,
    .state = state_advance(state, 2),
    .ok = { .kind = RESULT_U2, .u2 = read_u2(state_current(state), parser->u2.endian) }
  };
}

ALWAYS_INLINE
ParserResult parse_u4(ParserState state, Parser *parser) {
  assert(parser->kind == PARSER_U4);

  if (!state_has_bytes(state, 4)) {
    return result_fail_empty(state, parser);
  }

  return (ParserResult){
    .kind = RESULT_CONSUMED_OK,
    .state = state_advance(state, 4),
    .ok = { .kind = RESULT_U4, .u4 = read_u4(state_current(state), parser->u4.endian) }
  };
}

ALWAYS_INLINE
ParserResult parse_u8(ParserState state, Parser *parser) {
  assert(parser->kind == PARSER_U8);

  if (!state_has_bytes(state, 8)) {
    return result_fail_empty(state, parser);
  }

  return (ParserResult){
    .kind = RESULT_CONSUMED_OK,
    .state = state_advance(state, 8),
    .ok = { .kind = RESULT_U8, .u8 = read_u8(state_current(state), parser->u8.endian) }
  };
}

ALWAYS_INLINE
ParserResult parse_capture(ParserState state, Parser *parser) {
  assert(parser->kind == PARSER_CAPTURE);
  assert(parser->capture.parser != nullptr);
  assert(parser->capture.output != nullptr);

  auto res = parse_rec(state, parser->capture.parser);
  switch (res.kind) {
    case RESULT_CONSUMED_OK:
    case RESULT_EMPTY_OK:
      switch (res.ok.kind) {
        case RESULT_U2:
          *(uint16_t*)(parser->capture.output) = res.ok.u2;
          return res;
        case RESULT_U4:
          *(uint32_t*)(parser->capture.output) = res.ok.u4;
          return res;
        case RESULT_U8:
          *(uint64_t*)(parser->capture.output) = res.ok.u8;
          return res;
      }
      assert(0 && "Unsupported capture result type");
    case RESULT_CONSUMED_ERROR:
    case RESULT_EMPTY_ERROR:
      return res;
  }
}

ALWAYS_INLINE
ParserResult parse_const(ParserState state, Parser *parser) {
  assert(parser->kind == PARSER_CONST);

  ParserResult res = parse_rec(state, parser->constant.parser);
  switch (res.kind) {
    case RESULT_CONSUMED_OK:
    case RESULT_EMPTY_OK:
      switch (res.ok.kind) {
        case RESULT_U2:
          if (res.ok.u2 == parser->constant.u2) {
            return res;
          } else {
            return (ParserResult){
              .kind = res.kind == RESULT_CONSUMED_OK ? RESULT_CONSUMED_ERROR : RESULT_EMPTY_ERROR,
              .state = state, // do not advance
              .error = { .expected = parser }
            };
          }
        case RESULT_U4:
          if (res.ok.u4 == parser->constant.u4) {
            return res;
          } else {
            return (ParserResult){
              .kind = res.kind == RESULT_CONSUMED_OK ? RESULT_CONSUMED_ERROR : RESULT_EMPTY_ERROR,
              .state = state, // do not advance
              .error = { .expected = parser }
            };
          }
        case RESULT_U8:
          if (res.ok.u8 == parser->constant.u8) {
            return res;
          } else {
            return (ParserResult){
              .kind = res.kind == RESULT_CONSUMED_OK ? RESULT_CONSUMED_ERROR : RESULT_EMPTY_ERROR,
              .state = state, // do not advance
              .error = { .expected = parser }
            };
          }
      }
      assert(0 && "Unsupported constant parser result type");
    case RESULT_CONSUMED_ERROR:
      return res;
    case RESULT_EMPTY_ERROR:
      return res;
  }
}

ALWAYS_INLINE
ParserResult parse_seq(ParserState state, Parser *parser) {
  assert(parser->kind == PARSER_SEQ);
  assert(parser->seq.parsers != nullptr);

  auto res = (ParserResult){ .kind = RESULT_EMPTY_OK, .state = state };

  bool consumed = false;

  for (auto p = parser->seq.parsers; *p != nullptr; p++) {
    res = parse_rec(res.state, *p);
    switch (res.kind) {
      case RESULT_CONSUMED_OK:
        consumed = true;
        continue;
      case RESULT_EMPTY_OK:
        res.state = res.state;
        continue;
      case RESULT_CONSUMED_ERROR:
        return res;
      case RESULT_EMPTY_ERROR:
        if (consumed) {
          return result_fail_consumed(res.state, res.error.expected);
        } else {
          return res;
        }
    }
    assert(0 && "Unexpected result kind in SEQ parser");
  }

  return res;
}

ParserResult parse_alt(ParserState state, Parser *parser) {
  assert(parser->kind == PARSER_ALT);
  assert(parser->alt.parsers != nullptr);

  for (auto p = parser->alt.parsers; *p != nullptr; p++) {
    auto res = parse_rec(state, *p);
    switch (res.kind) {
      case RESULT_CONSUMED_OK:
        return res;
      case RESULT_EMPTY_OK:
        return res;
      case RESULT_CONSUMED_ERROR:
        return res;
      case RESULT_EMPTY_ERROR:
        continue;
    }
    assert(0 && "Unexpected result kind in ALT parser");
  }

  return result_fail_empty(state, parser);
}

ALWAYS_INLINE
ParserResult parse_rec(ParserState state, Parser *parser) {
  switch (parser->kind) {
    case PARSER_SKIP:
      return parse_skip(state, parser);
    case PARSER_U2:
      return parse_u2(state, parser);
    case PARSER_U4:
      return parse_u4(state, parser);
    case PARSER_U8:
      return parse_u8(state, parser);
    case PARSER_CAPTURE:
      return parse_capture(state, parser);
    case PARSER_CONST:
      return parse_const(state, parser);
    case PARSER_SEQ:
      return parse_seq(state, parser);
    case PARSER_ALT:
      return parse_alt(state, parser);
  }
  assert(0 && "Unknown parser kind");
}

// ==============================================================

typedef struct {
  char *data;
  size_t count;
  size_t capacity;
} String_Builder;

void sb_printf(String_Builder *sb, const char *fmt, ...) {
  va_list args;

  va_start(args, fmt);
  size_t needed = vsnprintf(nullptr, 0, fmt, args);
  va_end(args);

  if (sb->count + needed + 1 > sb->capacity) {
    sb->capacity = (sb->count + needed + 1) * 2;
    sb->data = realloc(sb->data, sb->capacity);
  }

  va_start(args, fmt);
  vsnprintf(sb->data + sb->count, sb->capacity - sb->count, fmt, args);
  va_end(args);

  sb->count += needed;
}

// ==============================================================

size_t parser_min_size(Parser *parser);

size_t parser_min_size_skip(Parser *parser) {
  assert(parser->kind == PARSER_SKIP);
  return parser->skip.count;
}

size_t parser_min_size_u2(Parser *parser) {
  assert(parser->kind == PARSER_U2);
  return 2;
}

size_t parser_min_size_u4(Parser *parser) {
  assert(parser->kind == PARSER_U4);
  return 4;
}

size_t parser_min_size_u8(Parser *parser) {
  assert(parser->kind == PARSER_U8);
  return 8;
}

size_t parser_min_size_capture(Parser *parser) {
  assert(parser->kind == PARSER_CAPTURE);
  return parser_min_size(parser->capture.parser);
}

size_t parser_min_size_const(Parser *parser) {
  assert(parser->kind == PARSER_CONST);
  return parser_min_size(parser->constant.parser);
}

size_t parser_min_size_seq(Parser *parser) {
  assert(parser->kind == PARSER_SEQ);
  size_t total = 0;
  for (auto p = parser->seq.parsers; *p != nullptr; p++) {
    total += parser_min_size(*p);
  }
  return total;
}

size_t parser_min_size_alt(Parser *parser) {
  assert(parser->kind == PARSER_ALT);
  size_t min_size = SIZE_MAX;
  for (auto p = parser->alt.parsers; *p != nullptr; p++) {
    size_t sz = parser_min_size(*p);
    if (sz < min_size) {
      min_size = sz;
    }
  }
  return min_size;
}

size_t parser_min_size(Parser *parser) {
  switch (parser->kind) {
    case PARSER_SKIP:
      return parser_min_size_skip(parser);
    case PARSER_U2:
      return parser_min_size_u2(parser);
    case PARSER_U4:
      return parser_min_size_u4(parser);
    case PARSER_U8:
      return parser_min_size_u8(parser);
    case PARSER_CAPTURE:
      return parser_min_size_capture(parser);
    case PARSER_CONST:
      return parser_min_size_const(parser);
    case PARSER_SEQ:
      return parser_min_size_seq(parser);
    case PARSER_ALT: 
      return parser_min_size_alt(parser);
  }
  assert(0 && "Unknown parser kind");
}

// ==============================================================

void fmt_parser_rec(String_Builder *sb, Parser *parser);

void fmt_parser(String_Builder *sb, Parser *parser) {
  fmt_parser_rec(sb, parser);
}

void fmt_parser_error(String_Builder *sb, ParserResult res) {
  assert(res.kind == RESULT_CONSUMED_ERROR || res.kind == RESULT_EMPTY_ERROR);
  assert(res.error.expected != nullptr);

  auto n = parser_min_size(res.error.expected);

  if (n <= 64) {
    for (size_t i = 0; i < n && res.state.offset + i < res.state.count; i++) {
      sb_printf(sb, "%02X ", res.state.data[res.state.offset + i]);
    }
    sb_printf(sb, "\n");
    sb_printf(sb, "^^\n");
  }

  sb_printf(sb, "Parse error at offset %zu: expected ", res.state.offset);
  fmt_parser(sb, res.error.expected);
  sb_printf(sb, "\n");
}

void fmt_parser_skip(String_Builder *sb, Parser *parser) {
  sb_printf(sb, "SKIP(%zu)", parser->skip.count);
}

void fmt_parser_u2(String_Builder *sb, Parser *parser) {
  sb_printf(sb, "U2(%s)", parser->u2.endian == ENDIAN_LE ? "LE" : "BE");
}

void fmt_parser_u4(String_Builder *sb, Parser *parser) {
  sb_printf(sb, "U4(%s)", parser->u4.endian == ENDIAN_LE ? "LE" : "BE");
}

void fmt_parser_u8(String_Builder *sb, Parser *parser) {
  sb_printf(sb, "U8(%s)", parser->u8.endian == ENDIAN_LE ? "LE" : "BE");
}

void fmt_parser_capture(String_Builder *sb, Parser *parser) {
  fmt_parser_rec(sb, parser->capture.parser);
}

void fmt_parser_const(String_Builder *sb, Parser *parser) {
  switch (parser->constant.parser->kind) {
    case PARSER_U2:
      sb_printf(sb, "CONST_U2(0x%04X, ", parser->constant.u2);
      fmt_parser_rec(sb, parser->constant.parser);
      sb_printf(sb, ")");
      break;
    case PARSER_U4:
      sb_printf(sb, "CONST_U4(0x%08X, ", parser->constant.u4);
      fmt_parser_rec(sb, parser->constant.parser);
      sb_printf(sb, ")");
      break;
    case PARSER_U8:
      sb_printf(sb, "CONST_U8(0x%016lX, ", parser->constant.u8);
      fmt_parser_rec(sb, parser->constant.parser);
      sb_printf(sb, ")");
      break;
    default:
      assert(0 && "Unsupported constant parser type");
  }
}

void fmt_parser_seq(String_Builder *sb, Parser *parser) {
  sb_printf(sb, "SEQ(");
  bool first = true;
  for (auto p = parser->seq.parsers; *p != nullptr; p++) {
    if (!first) {
      sb_printf(sb, ", ");
    }
    fmt_parser_rec(sb, *p);
    first = false;
  }
  sb_printf(sb, ")");
}

void fmt_parser_alt(String_Builder *sb, Parser *parser) {
  sb_printf(sb, "ALT(");
  bool first = true;
  for (auto p = parser->alt.parsers; *p != nullptr; p++) {
    if (!first) {
      sb_printf(sb, ", ");
    }
    fmt_parser_rec(sb, *p);
    first = false;
  }
  sb_printf(sb, ")");
}

void fmt_parser_rec(String_Builder *sb, Parser *parser) {
  switch (parser->kind) {
    case PARSER_SKIP:
      return fmt_parser_skip(sb, parser);
    case PARSER_U2:
      return fmt_parser_u2(sb, parser);
    case PARSER_U4:
      return fmt_parser_u4(sb, parser);
    case PARSER_U8:
      return fmt_parser_u8(sb, parser);
    case PARSER_CAPTURE:
      return fmt_parser_capture(sb, parser);
    case PARSER_CONST:
      return fmt_parser_const(sb, parser);
    case PARSER_SEQ:
      return fmt_parser_seq(sb, parser);
    case PARSER_ALT: 
      return fmt_parser_alt(sb, parser);
  }
  assert(0 && "Unknown parser kind");
}

// ==============================================================

typedef struct {
  uint8_t *data;
  size_t count;
  size_t capacity;
} Byte_Buffer;

bool bb_ensure(Byte_Buffer *bb, size_t n) {
  if (bb->count + n > bb->capacity) {
    size_t new_capacity = (bb->count + n) * 2;
    uint8_t *new_data = realloc(bb->data, new_capacity);
    if (new_data == nullptr) {
      return false;
    }
    bb->data = new_data;
    bb->capacity = new_capacity;
  }
  return true;
}

bool bb_read_file(Byte_Buffer *bb, const char *path) {
  FILE *file = fopen(path, "rb");
  if (file == nullptr) {
    return false;
  }

  fseek(file, 0, SEEK_END);
  size_t file_size = ftell(file);
  fseek(file, 0, SEEK_SET);

  if (!bb_ensure(bb, file_size)) {
    fclose(file);
    return false;
  }

  size_t read_size = fread(bb->data + bb->count, 1, file_size, file);
  fclose(file);

  if (read_size != file_size) {
    return false;
  }

  bb->count += read_size;
  return true;
}

ALWAYS_INLINE
ParserState bb_to_parser_state(Byte_Buffer bb) {
  return (ParserState){ .data = bb.data, .count = bb.count, .offset = 0 };
}

// ==============================================================

bool result_handle(ParserResult res, String_Builder *out_error) {
  switch (res.kind) {
    case RESULT_CONSUMED_OK:
    case RESULT_EMPTY_OK:
      return true;
    case RESULT_CONSUMED_ERROR:
    case RESULT_EMPTY_ERROR: {
      if (out_error != nullptr) {
        fmt_parser_error(out_error, res);
      }
      return false;
    }
  }
}

// ==============================================================

typedef struct {
  uint16_t machine;
  uint16_t number_of_sections;
  uint32_t time_date_stamp;
  uint32_t pointer_to_symbol_table;
  uint32_t number_of_symbols;
  uint16_t size_of_optional_header;
  uint16_t characteristics;
} COFF_Header;

#define COFF_MAGIC_PE32   0x10B
#define COFF_MAGIC_PE32P  0x20B

typedef struct {
  uint16_t magic;
  uint8_t major_linker_version;
  uint8_t minor_linker_version;
  uint32_t size_of_code;
  uint32_t size_of_initialized_data;
  uint32_t size_of_uninitialized_data;
  uint32_t address_of_entry_point;
  uint32_t base_of_code;
  uint32_t base_of_data;
} COFF_Standard_Fields;

typedef struct {
  uint32_t image_base;
  uint32_t section_alignment;
  uint32_t file_alignment;
  uint16_t major_operating_system_version;
  uint16_t minor_operating_system_version;
  uint16_t major_image_version;
  uint16_t minor_image_version;
  uint16_t major_subsystem_version;
  uint16_t minor_subsystem_version;
  uint32_t win32_version_value;
  uint32_t size_of_image;
  uint32_t size_of_headers;
  uint32_t check_sum;
  uint16_t subsystem;
  uint16_t dll_characteristics;
  uint32_t size_of_stack_reserve;
  uint32_t size_of_stack_commit;
  uint32_t size_of_heap_reserve;
  uint32_t size_of_heap_commit;
  uint32_t loader_flags;
  uint32_t number_of_rva_and_sizes;
} COFF_Windows_Fields_PE32;

typedef struct {
  uint64_t image_base;
  uint32_t section_alignment;
  uint32_t file_alignment;
  uint16_t major_operating_system_version;
  uint16_t minor_operating_system_version;
  uint16_t major_image_version;
  uint16_t minor_image_version;
  uint16_t major_subsystem_version;
  uint16_t minor_subsystem_version;
  uint32_t win32_version_value;
  uint32_t size_of_image;
  uint32_t size_of_headers;
  uint32_t check_sum;
  uint16_t subsystem;
  uint16_t dll_characteristics;
  uint64_t size_of_stack_reserve;
  uint64_t size_of_stack_commit;
  uint64_t size_of_heap_reserve;
  uint64_t size_of_heap_commit;
  uint32_t loader_flags;
  uint32_t number_of_rva_and_sizes;
} COFF_Windows_Fields_PE32P;

typedef union {
  COFF_Windows_Fields_PE32 pe32;
  COFF_Windows_Fields_PE32P pe32p;
} COFF_Windows_Fields;

typedef struct {
  uint32_t virtual_address;
  uint32_t size;
} Image_Data_Directory;

typedef struct {
  COFF_Header coff_header;
  COFF_Standard_Fields standard_fields;
  COFF_Windows_Fields windows_fields;
} PE_File;

void print_coff_header(const COFF_Header *header) {
  printf("Machine: 0x%04X\n", header->machine);
  printf("Number of Sections: %u\n", header->number_of_sections);
  printf("Time Date Stamp: %u\n", header->time_date_stamp);
  printf("Pointer to Symbol Table: %u\n", header->pointer_to_symbol_table);
  printf("Number of Symbols: %u\n", header->number_of_symbols);
  printf("Size of Optional Header: %u\n", header->size_of_optional_header);
  printf("Characteristics: 0x%04X\n", header->characteristics);
}

void print_coff_standard_fields(const COFF_Standard_Fields *fields) {
  printf("Magic: 0x%04X\n", fields->magic);
  printf("Linker Version: %u.%u\n", fields->major_linker_version, fields->minor_linker_version);
  printf("Size of Code: %u\n", fields->size_of_code);
  printf("Size of Initialized Data: %u\n", fields->size_of_initialized_data);
  printf("Size of Uninitialized Data: %u\n", fields->size_of_uninitialized_data);
  printf("Address of Entry Point: 0x%08X\n", fields->address_of_entry_point);
  printf("Base of Code: 0x%08X\n", fields->base_of_code);
  printf("Base of Data: 0x%08X\n", fields->base_of_data);
}

void print_coff_windows_fields_pe32(const COFF_Windows_Fields_PE32 *fields) {
  printf("Image Base: 0x%08X\n", fields->image_base);
  printf("Section Alignment: %u\n", fields->section_alignment);
  printf("File Alignment: %u\n", fields->file_alignment);
  printf("Operating System Version: %u.%u\n", fields->major_operating_system_version, fields->minor_operating_system_version);
  printf("Image Version: %u.%u\n", fields->major_image_version, fields->minor_image_version);
  printf("Subsystem Version: %u.%u\n", fields->major_subsystem_version, fields->minor_subsystem_version);
  printf("Win32 Version Value: %u\n", fields->win32_version_value);
  printf("Size of Image: %u\n", fields->size_of_image);
  printf("Size of Headers: %u\n", fields->size_of_headers);
  printf("Check Sum: %u\n", fields->check_sum);
  printf("Subsystem: 0x%04X\n", fields->subsystem);
  printf("DLL Characteristics: 0x%04X\n", fields->dll_characteristics);
  printf("Size of Stack Reserve: %u\n", fields->size_of_stack_reserve);
  printf("Size of Stack Commit: %u\n", fields->size_of_stack_commit);
  printf("Size of Heap Reserve: %u\n", fields->size_of_heap_reserve);
  printf("Size of Heap Commit: %u\n", fields->size_of_heap_commit);
  printf("Loader Flags: %u\n", fields->loader_flags);
  printf("Number of RVA and Sizes: %u\n", fields->number_of_rva_and_sizes);
}

void print_coff_windows_fields_pe32p(const COFF_Windows_Fields_PE32P *fields) {
  printf("Image Base: 0x%016llX\n", fields->image_base);
  printf("Section Alignment: %u\n", fields->section_alignment);
  printf("File Alignment: %u\n", fields->file_alignment);
  printf("Operating System Version: %u.%u\n", fields->major_operating_system_version, fields->minor_operating_system_version);
  printf("Image Version: %u.%u\n", fields->major_image_version, fields->minor_image_version);
  printf("Subsystem Version: %u.%u\n", fields->major_subsystem_version, fields->minor_subsystem_version);
  printf("Win32 Version Value: %u\n", fields->win32_version_value);
  printf("Size of Image: %u\n", fields->size_of_image);
  printf("Size of Headers: %u\n", fields->size_of_headers);
  printf("Check Sum: %u\n", fields->check_sum);
  printf("Subsystem: 0x%04X\n", fields->subsystem);
  printf("DLL Characteristics: 0x%04X\n", fields->dll_characteristics);
  printf("Size of Stack Reserve: %llu\n", fields->size_of_stack_reserve);
  printf("Size of Stack Commit: %llu\n", fields->size_of_stack_commit);
  printf("Size of Heap Reserve: %llu\n", fields->size_of_heap_reserve);
  printf("Size of Heap Commit: %llu\n", fields->size_of_heap_commit);
  printf("Loader Flags: %u\n", fields->loader_flags);
  printf("Number of RVA and Sizes: %u\n", fields->number_of_rva_and_sizes);
}

bool parse_pe_file(Byte_Buffer *bb, PE_File *out_file, String_Builder *out_error) {
  auto pstate = bb_to_parser_state(*bb);

  uint32_t pe_header_offset;

  {
    auto parser = SEQ(
      CONST_U2(0x5A4D, U2_LE()),
      SKIP(0x3C - 2),
      CAPTURE(&pe_header_offset, U4_LE())
    );

    auto res = parser_run(pstate, parser);
    if (!result_handle(res, out_error)) {
      return false;
    }
  }

  auto coff_header = (COFF_Header){0};

  auto coff_header_parser = SEQ(
    SKIP(pe_header_offset),
    CONST_U4(0x50450000, U4_BE()), // "PE\0\0"
    CAPTURE(&coff_header.machine, U2_LE()),
    CAPTURE(&coff_header.number_of_sections, U2_LE()),
    CAPTURE(&coff_header.time_date_stamp, U4_LE()),
    CAPTURE(&coff_header.pointer_to_symbol_table, U4_LE()),
    CAPTURE(&coff_header.number_of_symbols, U4_LE()),
    CAPTURE(&coff_header.size_of_optional_header, U2_LE()),
    CAPTURE(&coff_header.characteristics, U2_LE())
  );

  {
    auto res = parser_run(bb_to_parser_state(*bb), coff_header_parser);
    if (!result_handle(res, out_error)) {
      return false;
    }
    pstate = res.state;
  }

  auto standard_fields = (COFF_Standard_Fields){0};

  {
    auto common = SEQ(
      CAPTURE(&standard_fields.major_linker_version, SKIP(1)),
      CAPTURE(&standard_fields.minor_linker_version, SKIP(1)),
      CAPTURE(&standard_fields.size_of_code, U4_LE()),
      CAPTURE(&standard_fields.size_of_initialized_data, U4_LE()),
      CAPTURE(&standard_fields.size_of_uninitialized_data, U4_LE()),
      CAPTURE(&standard_fields.address_of_entry_point, U4_LE()),
      CAPTURE(&standard_fields.base_of_code, U4_LE())
    );

    auto parser = ALT(
      SEQ(
        CAPTURE(&standard_fields.magic, CONST_U2(COFF_MAGIC_PE32, U2_LE())),
        common,
        // PE32 has BaseOfData
        CAPTURE(&standard_fields.base_of_data, U4_LE())
      ),
      SEQ(
        CAPTURE(&standard_fields.magic, CONST_U2(COFF_MAGIC_PE32P, U2_LE())),
        common
      )
    );
    
    auto res = parser_run(pstate, parser);
    if (!result_handle(res, out_error)) {
      return false;
    }

    pstate = res.state;
  }

  COFF_Windows_Fields windows_fields = {0};

  if (standard_fields.magic == COFF_MAGIC_PE32) {
    // Parse PE32 Windows-Specific Fields
    auto fields = (COFF_Windows_Fields_PE32){0};

    auto parser = SEQ(
      CAPTURE(&fields.image_base, U4_LE()),
      CAPTURE(&fields.section_alignment, U4_LE()),
      CAPTURE(&fields.file_alignment, U4_LE()),
      CAPTURE(&fields.major_operating_system_version, U2_LE()),
      CAPTURE(&fields.minor_operating_system_version, U2_LE()),
      CAPTURE(&fields.major_image_version, U2_LE()),
      CAPTURE(&fields.minor_image_version, U2_LE()),
      CAPTURE(&fields.major_subsystem_version, U2_LE()),
      CAPTURE(&fields.minor_subsystem_version, U2_LE()),
      CAPTURE(&fields.win32_version_value, U4_LE()),
      CAPTURE(&fields.size_of_image, U4_LE()),
      CAPTURE(&fields.size_of_headers, U4_LE()),
      CAPTURE(&fields.check_sum, U4_LE()),
      CAPTURE(&fields.subsystem, U2_LE()),
      CAPTURE(&fields.dll_characteristics, U2_LE()),
      CAPTURE(&fields.size_of_stack_reserve, U4_LE()),
      CAPTURE(&fields.size_of_stack_commit, U4_LE()),
      CAPTURE(&fields.size_of_heap_reserve, U4_LE()),
      CAPTURE(&fields.size_of_heap_commit, U4_LE()),
      CAPTURE(&fields.loader_flags, U4_LE()),
      CAPTURE(&fields.number_of_rva_and_sizes, U4_LE())
    );

    auto res = parser_run(pstate, parser);
    if (!result_handle(res, out_error)) {
      return false;
    }

    pstate = res.state;
    windows_fields.pe32 = fields;
  } else if (standard_fields.magic == COFF_MAGIC_PE32P) {
    // Parse PE32+ Windows-Specific Fields
    auto fields = (COFF_Windows_Fields_PE32P){0};

    auto parser = SEQ(
      CAPTURE(&fields.image_base, U8_LE()),
      CAPTURE(&fields.section_alignment, U4_LE()),
      CAPTURE(&fields.file_alignment, U4_LE()),
      CAPTURE(&fields.major_operating_system_version, U2_LE()),
      CAPTURE(&fields.minor_operating_system_version, U2_LE()),
      CAPTURE(&fields.major_image_version, U2_LE()),
      CAPTURE(&fields.minor_image_version, U2_LE()),
      CAPTURE(&fields.major_subsystem_version, U2_LE()),
      CAPTURE(&fields.minor_subsystem_version, U2_LE()),
      CAPTURE(&fields.win32_version_value, U4_LE()),
      CAPTURE(&fields.size_of_image, U4_LE()),
      CAPTURE(&fields.size_of_headers, U4_LE()),
      CAPTURE(&fields.check_sum, U4_LE()),
      CAPTURE(&fields.subsystem, U2_LE()),
      CAPTURE(&fields.dll_characteristics, U2_LE()),
      CAPTURE(&fields.size_of_stack_reserve, U8_LE()),
      CAPTURE(&fields.size_of_stack_commit, U8_LE()),
      CAPTURE(&fields.size_of_heap_reserve, U8_LE()),
      CAPTURE(&fields.size_of_heap_commit, U8_LE()),
      CAPTURE(&fields.loader_flags, U4_LE()),
      CAPTURE(&fields.number_of_rva_and_sizes, U4_LE())
    );

    auto res = parser_run(pstate, parser);
    if (!result_handle(res, out_error)) {
      return false;
    }

    pstate = res.state;
    windows_fields.pe32p = fields;
  } else {
    sb_printf(out_error, "Unknown PE magic: 0x%04X\n", standard_fields.magic);
    return false;
  }

  *out_file = (PE_File){
    .coff_header = coff_header,
    .standard_fields = standard_fields,
    .windows_fields = windows_fields,
  };

  return true;
}

// ==============================================================

int main() {
  Byte_Buffer bb = {0};
  String_Builder error = {0};

  if (!bb_read_file(&bb, "build/Main.dll")) return 1;

  printf("Read %zu bytes from file.\n", bb.count);

  PE_File pe_file = {0};
  if (!parse_pe_file(&bb, &pe_file, &error)) {
    fprintf(stderr, "%.*s\n", (int)error.count, error.data);
    free(error.data);
    return 1;
  }
  
  print_coff_header(&pe_file.coff_header);
  print_coff_standard_fields(&pe_file.standard_fields);
  if (pe_file.standard_fields.magic == COFF_MAGIC_PE32) {
    print_coff_windows_fields_pe32(&pe_file.windows_fields.pe32);
  } else if (pe_file.standard_fields.magic == COFF_MAGIC_PE32P) {
    print_coff_windows_fields_pe32p(&pe_file.windows_fields.pe32p);
  }

  return 0;
}
