#include <assert.h>
#include <stdarg.h>
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

// ==============================================================

typedef struct Parser {
  enum {
    // Primitive parsers
    PARSER_SKIP,
    PARSER_U2,
    PARSER_U4,

    // Composite parsers
    PARSER_CAPTURE,
    PARSER_CONST,
    PARSER_SEQ,
  } kind;
  union {
    struct { size_t count; } skip;
    struct { int endian; } u2;
    struct { int endian; } u4;
    struct {
      struct Parser *parser;
      void *output;
    } capture;
    struct {
      struct Parser *parser;
      union {
        uint16_t u2;
        uint32_t u4;
      };
    } constant;
    struct { struct Parser **parsers; } seq;
  };
} Parser;

#define U2_LE() (&(Parser){ .kind = PARSER_U2, .u2 = { .endian = ENDIAN_LE } })
#define U2_BE() (&(Parser){ .kind = PARSER_U2, .u2 = { .endian = ENDIAN_BE } })
#define U4_LE() (&(Parser){ .kind = PARSER_U4, .u4 = { .endian = ENDIAN_LE } })
#define U4_BE() (&(Parser){ .kind = PARSER_U4, .u4 = { .endian = ENDIAN_BE } })

#define SKIP(n) (&(Parser){ .kind = PARSER_SKIP, .skip = { .count = n } })

#define CAPTURE(o, p) (&(Parser){ .kind = PARSER_CAPTURE, .capture = { .parser = p, .output = o } })

#define CONST_U2(value, p) (&(Parser){ .kind = PARSER_CONST, .constant = { .u2 = value, .parser = p } })
#define CONST_U4(value, p) (&(Parser){ .kind = PARSER_CONST, .constant = { .u4 = value, .parser = p } })

#define SEQ(...) (&(Parser){ .kind = PARSER_SEQ, .seq = { (Parser*[]){ __VA_ARGS__, nullptr } } })

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
      } kind;
      union {
        uint16_t u2;
        uint32_t u4;
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

ALWAYS_INLINE
ParserResult parse_rec(ParserState state, Parser *parser) {
  switch (parser->kind) {
    case PARSER_SKIP:
      return parse_skip(state, parser);
    case PARSER_U2:
      return parse_u2(state, parser);
    case PARSER_U4:
      return parse_u4(state, parser);
    case PARSER_CAPTURE:
      return parse_capture(state, parser);
    case PARSER_CONST:
      return parse_const(state, parser);
    case PARSER_SEQ:
      return parse_seq(state, parser);
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

size_t parser_min_size(Parser *parser) {
  switch (parser->kind) {
    case PARSER_SKIP:
      return parser_min_size_skip(parser);
    case PARSER_U2:
      return parser_min_size_u2(parser);
    case PARSER_U4:
      return parser_min_size_u4(parser);
    case PARSER_CAPTURE:
      return parser_min_size_capture(parser);
    case PARSER_CONST:
      return parser_min_size_const(parser);
    case PARSER_SEQ:
      return parser_min_size_seq(parser);
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

void fmt_parser_rec(String_Builder *sb, Parser *parser) {
  switch (parser->kind) {
    case PARSER_SKIP:
      return fmt_parser_skip(sb, parser);
    case PARSER_U2:
      return fmt_parser_u2(sb, parser);
    case PARSER_U4:
      return fmt_parser_u4(sb, parser);
    case PARSER_CAPTURE:
      return fmt_parser_capture(sb, parser);
    case PARSER_CONST:
      return fmt_parser_const(sb, parser);
    case PARSER_SEQ:
      return fmt_parser_seq(sb, parser);
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

typedef struct {
  COFF_Header coff_header;
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

bool parse_pe_file(Byte_Buffer *bb, PE_File *out_file, String_Builder *out_error) {
  uint32_t pe_header_offset;

  auto dos_header_parser = SEQ(
    CONST_U2(0x5A4D, U2_LE()),
    SKIP(0x3C - 2),
    CAPTURE(&pe_header_offset, U4_LE())
  );

  {
    auto res = parser_run(bb_to_parser_state(*bb), dos_header_parser);
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
  }

  *out_file = (PE_File){
    .coff_header = coff_header
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

  return 0;
}
