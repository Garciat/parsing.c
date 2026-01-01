#include <assert.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ==============================================================
// # Utilities
// ==============================================================

typedef struct {
  const char *data;
  size_t size;
} String_View;

String_View sv_from_cstr(const char *cstr) {
  return (String_View){ .data=cstr, .size=strlen(cstr) };
}

typedef struct {
  char *items;
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
    sb->items = realloc(sb->items, sb->capacity);
  }

  va_start(args, fmt);
  vsnprintf(sb->items + sb->count, sb->capacity - sb->count, fmt, args);
  va_end(args);

  sb->count += needed;
}

// ==============================================================
// # Node Definitions
// ==============================================================

typedef struct Node {
  enum { 
    NODE_END,
    NODE_ANY,
    NODE_STRING,
    NODE_ONEOF,
    NODE_RANGE,
    NODE_SOME,
    NODE_MANY,
    NODE_OPT,
    NODE_SEQ,
    NODE_ALT,
    NODE_NOT,
    NODE_TRY,

    NODE_CAPTURE,
  } type;

  union {
    // struct { } end;
    // struct { } any;
    struct { char *str; } string;
    struct { char *chars; } oneof;
    struct { char from, to; } range;
    struct { struct Node *node; } some;
    struct { struct Node *node; } many;
    struct { struct Node *node; } opt;
    struct { struct Node **nodes; } seq;
    struct { struct Node **nodes; } alt;
    struct { struct Node *node; } not;
    struct { struct Node *node; } try;
    struct { struct Node *node; String_View *output; } capture;
  } data;
} Node;

#define END()              (&(Node){ .type = NODE_END }) 
#define ANY()              (&(Node){ .type = NODE_ANY })
#define STR(s)             (&(Node){ .type = NODE_STRING, .data.string = { s } })
#define ONEOF(chars)       (&(Node){ .type = NODE_ONEOF, .data.oneof = { chars } })
#define RANGE(from, to)    (&(Node){ .type = NODE_RANGE, .data.range = { from, to } })
#define SOME(n)            (&(Node){ .type = NODE_SOME, .data.some = { n } })
#define MANY(n)            (&(Node){ .type = NODE_MANY, .data.many = { n } })
#define OPT(n)             (&(Node){ .type = NODE_OPT, .data.opt = { n } })
#define SEQ(...)           (&(Node){ .type = NODE_SEQ, .data.seq = { (Node**)&(Node*[]){ __VA_ARGS__, nullptr } } })
#define ALT(...)           (&(Node){ .type = NODE_ALT, .data.alt = { (Node**)&(Node*[]){ __VA_ARGS__, nullptr } } })
#define NOT(n)             (&(Node){ .type = NODE_NOT, .data.not = { n } })
#define TRY(n)             (&(Node){ .type = NODE_TRY, .data.try = { n } })
#define CAPTURE(output, n) (&(Node){ .type = NODE_CAPTURE, .data.capture = { n, output } })

// ==============================================================
// # Matching Engine
// ==============================================================

typedef struct {
  String_View sv;
  size_t position;
} Match_State;

Match_State state_advance(Match_State state, size_t n) {
  assert(state.position + n <= state.sv.size);
  return (Match_State){ .sv = state.sv, .position = state.position + n };
}

typedef struct {
  Node *node;
  Match_State state;
} Match_Expect;

void fmt_expect(String_Builder *sb, Match_Expect expect);

typedef struct {
  enum {
    CONSUMED_OK,
    CONSUMED_ERROR,
    EMPTY_OK,
    EMPTY_ERROR
  } status;
  Match_State state;
  Node *expected;
} Match_Result;

Match_Expect result_to_expect(Match_Result res) {
  return (Match_Expect){ .node = res.expected, .state = res.state };
}

Match_Result match_rec(Node *node, Match_State state);

Match_Result match_end(Node *node, Match_State state) {
  if (state.position == state.sv.size) {
    return (Match_Result){ .status = EMPTY_OK, .state = state };
  }
  return (Match_Result){ .status = EMPTY_ERROR, .state = state, .expected = node };
}

Match_Result match_any(Node *node, Match_State state) {
  if (state.position < state.sv.size) {
    return (Match_Result){ .status = CONSUMED_OK, .state = state_advance(state, 1) };
  }
  return (Match_Result){ .status = EMPTY_ERROR, .state = state, .expected = node };
}

// Consumes prefix on failure
Match_Result match_string(Node *node, Match_State state) {
  assert(node->data.string.str != nullptr);

  size_t i = 0;
  for (; node->data.string.str[i] && state.position + i < state.sv.size; i++) {
    if (state.sv.data[state.position + i] != node->data.string.str[i]) {
      break;
    }
  }

  if (node->data.string.str[i] == '\0') {
    return (Match_Result){ .status = CONSUMED_OK, .state = state_advance(state, i) };
  } else if (i == 0) {
    return (Match_Result){ .status = EMPTY_ERROR, .state = state, .expected = node };
  } else {
    return (Match_Result){ .status = CONSUMED_ERROR, .state = state_advance(state, i), .expected = node };
  }
}

Match_Result match_oneof(Node *node, Match_State state) {
  assert(node->data.oneof.chars != nullptr);

  if (state.position < state.sv.size) {
    for (char *c = node->data.oneof.chars; *c != '\0'; c++) {
      if (state.sv.data[state.position] == *c) {
        return (Match_Result){ .status = CONSUMED_OK, .state = state_advance(state, 1) };
      }
    }
  }

  return (Match_Result){ .status = EMPTY_ERROR, .state = state, .expected = node };
}

Match_Result match_range(Node *node, Match_State state) {
  assert(node->data.range.from <= node->data.range.to);

  if (state.position < state.sv.size &&
      state.sv.data[state.position] >= node->data.range.from &&
      state.sv.data[state.position] <= node->data.range.to) {
    return (Match_Result){ .status = CONSUMED_OK, .state = state_advance(state, 1) };
  }
  
  return (Match_Result){ .status = EMPTY_ERROR, .state = state, .expected = node };
}

Match_Result match_many(Node *node, Match_State state) {
  assert(node->data.many.node != nullptr);

  auto res = (Match_Result){ .status = EMPTY_OK, .state = state };

  bool consumed = false;

  while (true) {
    res = match_rec(node->data.many.node, res.state);
    switch (res.status) {
      case CONSUMED_OK:
        consumed = true;
        continue;
      case EMPTY_OK:
        continue;
      case CONSUMED_ERROR:
        return res;
      case EMPTY_ERROR:
        if (consumed) {
          return (Match_Result){ .status = CONSUMED_OK, .state = res.state };
        } else {
          return (Match_Result){ .status = EMPTY_OK, .state = res.state };
        }
    }
  }
}

Match_Result match_some(Node *node, Match_State state) {
  assert(node->data.some.node != nullptr);

  auto res = match_rec(node->data.some.node, state);
  switch (res.status) {
    case CONSUMED_OK:
    case EMPTY_OK:
      break;
    case CONSUMED_ERROR:
    case EMPTY_ERROR:
      return res;
  }

  return match_many(node, res.state);
}

Match_Result match_opt(Node *node, Match_State state) {
  assert(node->data.opt.node != nullptr);

  auto res = match_rec(node->data.opt.node, state);
  switch (res.status) {
    case CONSUMED_OK:
    case EMPTY_OK:
    case CONSUMED_ERROR:
      return res;
    case EMPTY_ERROR:
      return (Match_Result){ .status = EMPTY_OK, .state = state };
  }
}

Match_Result match_seq(Node *node, Match_State state) {
  assert(node->data.seq.nodes != nullptr);

  auto res = (Match_Result){ .status = EMPTY_OK, .state = state };

  bool consumed = false;

  for (auto n = node->data.seq.nodes; *n != nullptr; n++) {
    res = match_rec(*n, res.state);
    switch (res.status) {
      case CONSUMED_OK:
        consumed = true;
        continue;
      case EMPTY_OK:
        continue;
      case CONSUMED_ERROR:
        return res;
      case EMPTY_ERROR:
        if (consumed) {
          return (Match_Result){ .status = CONSUMED_ERROR, .state = res.state, .expected = res.expected };
        } else {
          return res;
        }
    }
  }

  return res;
}

Match_Result match_alt(Node *node, Match_State state) {
  assert(node->data.alt.nodes != nullptr);

  for (auto n = node->data.alt.nodes; *n != nullptr; n++) {
    auto res = match_rec(*n, state);
    switch (res.status) {
      case CONSUMED_OK:
      case EMPTY_OK:
        return res;
      case CONSUMED_ERROR:
        return res;
      case EMPTY_ERROR:
        continue;
    }
  }

  return (Match_Result){ .status = EMPTY_ERROR, .state = state, .expected = node };
}

Match_Result match_not(Node *node, Match_State state) {
  assert(node->data.not.node != nullptr);

  auto res = match_rec(node->data.not.node, state);
  switch (res.status) {
    case CONSUMED_OK:
      return (Match_Result){ .status = CONSUMED_ERROR, .state = state, .expected = node };
    case EMPTY_OK:
      return (Match_Result){ .status = EMPTY_ERROR, .state = state, .expected = node };
    case CONSUMED_ERROR:
      return (Match_Result){ .status = CONSUMED_OK, .state = state };
    case EMPTY_ERROR:
      return (Match_Result){ .status = EMPTY_OK, .state = state };
  }
}

Match_Result match_try(Node *node, Match_State state) {
  assert(node->data.try.node != nullptr);

  auto res = match_rec(node->data.try.node, state);
  switch (res.status) {
    case CONSUMED_OK:
    case EMPTY_OK:
      return res;
    case CONSUMED_ERROR:
    case EMPTY_ERROR:
      return (Match_Result){ .status = EMPTY_ERROR, .state = state, .expected = res.expected };
  }
}

Match_Result match_capture(Node *node, Match_State state) {
  assert(node->data.capture.node != nullptr);
  assert(node->data.capture.output != nullptr);

  auto res = match_rec(node->data.capture.node, state);
  switch (res.status) {
    case CONSUMED_OK:
    case EMPTY_OK:
      *(node->data.capture.output) = (String_View){
        .data = state.sv.data + state.position,
        .size = res.state.position - state.position
      };
      return res;
    case CONSUMED_ERROR:
    case EMPTY_ERROR:
      return res;
  }
}

Match_Result match_rec(Node *node, Match_State state) {
  switch (node->type) {
    case NODE_END:
      return match_end(node, state);
    case NODE_ANY:
      return match_any(node, state);
    case NODE_STRING:
      return match_string(node, state);
    case NODE_ONEOF:
      return match_oneof(node, state);
    case NODE_RANGE:
      return match_range(node, state);
    case NODE_SOME:
      return match_some(node, state);
    case NODE_MANY:
      return match_many(node, state);
    case NODE_OPT:
      return match_opt(node, state);
    case NODE_SEQ:
      return match_seq(node, state);
    case NODE_ALT:
      return match_alt(node, state);
    case NODE_NOT:
      return match_not(node, state);
    case NODE_TRY:
      return match_try(node, state);
    case NODE_CAPTURE:
      return match_capture(node, state);
    default:
      assert(0 && "Unknown node type");
  }
}

bool match(Node *pattern, String_View input, String_Builder *out_expect) {
  auto res = match_rec(pattern, (Match_State){ .sv = input, .position = 0 });
  switch (res.status) {
    case CONSUMED_OK:
    case EMPTY_OK:
      return true;
    case CONSUMED_ERROR:
    case EMPTY_ERROR: {
      if (out_expect != nullptr) {
        fmt_expect(out_expect, result_to_expect(res));
      }
      return false;
    }
  }
}

bool match_cstr(Node *pattern, const char *input) {
  return match(pattern, sv_from_cstr(input), nullptr);
}

void fmt_pat(String_Builder *sb, Node *node);

// ==============================================================
// # URL Matching Example
// ==============================================================

typedef struct {
  String_View domain;
  String_View path;
} URL_Match;

bool match_url(const char *input, URL_Match *out, String_Builder *out_expect) {
  auto domain_char = ALT(
    RANGE('a', 'z'),
    RANGE('A', 'Z'),
    RANGE('0', '9'),
    ONEOF("-")
  );

  auto path_char = ALT(
    RANGE('a', 'z'),
    RANGE('A', 'Z'),
    RANGE('0', '9'),
    ONEOF("-_.")
  );

  auto pat = SEQ(
    STR("http"),
    OPT(STR("s")),
    STR("://"),
    CAPTURE(
      &out->domain,
      SEQ(
        SOME(domain_char),
        MANY(SEQ(STR("."), SOME(domain_char)))
      )
    ),
    CAPTURE(
      &out->path,
      MANY(SEQ(STR("/"), MANY(path_char)))
    ),
    END()
  );

  return match(pat, sv_from_cstr(input), out_expect);
}

// ==============================================================
// # Tests
// ==============================================================

void test_core();
void test_url();

int main() {
  test_core();
  test_url();
  return 0;
}

void test_end() {
  assert(match_cstr(END(), ""));
  assert(!match_cstr(END(), "a"));
}

void test_any() {
  assert(match_cstr(ANY(), "a"));
  assert(match_cstr(ANY(), "Z"));
  assert(!match_cstr(ANY(), ""));
}

void test_string() {
  assert(match_cstr(STR("hello"), "hello"));
  assert(match_cstr(STR("hello"), "hello!"));
  assert(!match_cstr(STR("hello"), "hell"));
}

void test_oneof() {
  assert(match_cstr(ONEOF("abc"), "a"));
  assert(match_cstr(ONEOF("abc"), "b"));
  assert(match_cstr(ONEOF("abc"), "c"));
  assert(!match_cstr(ONEOF("abc"), "d"));
  assert(!match_cstr(ONEOF("abc"), ""));
}

void test_range() {
  assert(match_cstr(RANGE('a', 'z'), "a"));
  assert(match_cstr(RANGE('a', 'z'), "m"));
  assert(match_cstr(RANGE('a', 'z'), "z"));
  assert(!match_cstr(RANGE('a', 'z'), "A"));
  assert(!match_cstr(RANGE('a', 'z'), "0"));
  assert(!match_cstr(RANGE('a', 'z'), ""));
}

void test_sequence() {
  assert(match_cstr(SEQ(STR("he"), STR("llo")), "hello"));
  assert(!match_cstr(SEQ(STR("he"), STR("llo")), "hell"));
}

void test_alternative() {
  assert(match_cstr(ALT(STR("cat"), STR("dog")), "cat"));
  assert(match_cstr(ALT(STR("cat"), STR("dog")), "dog"));
  assert(!match_cstr(ALT(STR("cat"), STR("dog")), "mouse"));
}

void test_some() {
  assert(match_cstr(SOME(RANGE('a', 'z')), "abcxyz"));
  assert(!match_cstr(SOME(RANGE('a', 'z')), "123"));
  assert(!match_cstr(SOME(RANGE('a', 'z')), ""));
}

void test_many() {
  assert(match_cstr(MANY(RANGE('a', 'z')), "abcxyz"));
  assert(match_cstr(MANY(RANGE('a', 'z')), ""));
  assert(match_cstr(MANY(RANGE('a', 'z')), "123"));
}

void test_opt() {
  assert(match_cstr(OPT(STR("hello")), "hello"));
  assert(match_cstr(OPT(STR("hello")), ""));
  assert(!match_cstr(OPT(STR("hello")), "hell"));
}

void test_not() {
  assert(match_cstr(NOT(STR("fail")), "success"));
  assert(!match_cstr(NOT(STR("fail")), "fail"));
}

void test_try() {
  assert(!match_cstr(ALT(STR("help"), STR("hello")), "hello"));
  assert(match_cstr(ALT(TRY(STR("help")), STR("hello")), "hello"));
}

void test_capture() {
  String_View captured;
  auto pat = CAPTURE(&captured, STR("hello"));

  assert(match_cstr(pat, "hello"));
  assert(captured.size == 5);
  assert(strncmp(captured.data, "hello", captured.size) == 0);

  assert(!match_cstr(pat, "hell"));
}

void test_misc() {
  assert(!match_cstr(MANY(SEQ(STR("."), SOME(RANGE('a', 'z')))), ".com.123"));
}

void test_core() {
  test_end();
  test_any();
  test_string();
  test_oneof();
  test_range();
  test_sequence();
  test_alternative();
  test_some();
  test_many();
  test_opt();
  test_not();
  test_try();
  test_capture();
  test_misc();
}

bool match_url_test(const char *input, URL_Match *out) {
  String_Builder expect = {0};
  bool r = match_url(input, out, &expect);
  if (!r) {
    fprintf(stderr, "%.*s\n", (int)expect.count, expect.items);
    free(expect.items);
  }
  return r;
}

bool match_url_fail_test(const char *input) {
  URL_Match out;
  return !match_url(input, &out, nullptr);
}

void test_url() {
  URL_Match url;
  assert(match_url_test("http://example.com/path", &url));
  assert(strncmp(url.domain.data, "example.com", url.domain.size) == 0);
  assert(strncmp(url.path.data, "/path", url.path.size) == 0);

  assert(match_url_test("https://sub.domain.org/", &url));
  assert(strncmp(url.domain.data, "sub.domain.org", url.domain.size) == 0);
  assert(strncmp(url.path.data, "/", url.path.size) == 0);

  assert(match_url_test("http://example/path", &url));
  assert(strncmp(url.domain.data, "example", url.domain.size) == 0);
  assert(strncmp(url.path.data, "/path", url.path.size) == 0);

  assert(match_url_fail_test("ftp://example.com/path"));
}

// ==============================================================
// # Debug Printing
// ==============================================================

void fmt_expect_rec(String_Builder *sb, Match_Expect expect);

void fmt_expect(String_Builder *sb, Match_Expect expect) {
  sb_printf(sb, "%.*s\n", (int)expect.state.sv.size, expect.state.sv.data);
  sb_printf(sb, "%*s^\n", (int)expect.state.position, "");

  sb_printf(sb, "Match failure at character %zu:\nExpected ", expect.state.position+1);
  fmt_expect_rec(sb, expect);
}

void fmt_expect_end(String_Builder *sb, Match_Expect) {
  sb_printf(sb, "end of input");
}

void fmt_expect_any(String_Builder *sb, Match_Expect) {
  sb_printf(sb, "any character");
}

void fmt_expect_string(String_Builder *sb, Match_Expect expect) {
  sb_printf(sb, "\"%s\"", expect.node->data.string.str);
}

void fmt_expect_oneof(String_Builder *sb, Match_Expect expect) {
  sb_printf(sb, "one of characters \"%s\"", expect.node->data.oneof.chars);
}

void fmt_expect_range(String_Builder *sb, Match_Expect expect) {
  sb_printf(sb, "character in range '%c'-'%c'", 
            expect.node->data.range.from,
            expect.node->data.range.to);
}

void fmt_expect_alt(String_Builder *sb, Match_Expect expect) {
  sb_printf(sb, "one of:\n");
  for (auto n = expect.node->data.alt.nodes; *n != nullptr; n++) {
    sb_printf(sb, "  ");
    fmt_expect_rec(sb, (Match_Expect){ .node = *n });
    sb_printf(sb, "\n");
  }
}

void fmt_expect_not(String_Builder *sb, Match_Expect expect) {
  sb_printf(sb, "not ");
  fmt_expect_rec(sb, (Match_Expect){ .node = expect.node->data.not.node });
}

void fmt_expect_rec(String_Builder *sb, Match_Expect expect) {
  switch (expect.node->type) {
    case NODE_END:
      return fmt_expect_end(sb, expect);
    case NODE_ANY:
      return fmt_expect_any(sb, expect);
    case NODE_STRING:
      return fmt_expect_string(sb, expect);
    case NODE_ONEOF:
      return fmt_expect_oneof(sb, expect);
    case NODE_RANGE:
      return fmt_expect_range(sb, expect);
    case NODE_ALT:
      return fmt_expect_alt(sb, expect);
    case NODE_NOT:
      return fmt_expect_not(sb, expect);
    default:
      sb_printf(sb, "<complex pattern>");
      return;
  }
}

// ==============================================================
// # Pattern Printing
// ==============================================================

bool is_special_char(char c) {
  return c == '.' || c == '*' || c == '+' || c == '?' ||
         c == '(' || c == ')' || c == '[' || c == ']' ||
         c == '{' || c == '}' || c == '|' || c == '^' ||
         c == '$' || c == '\\';
}

void fmt_pat_rec(String_Builder *sb, Node *node);

void fmt_pat(String_Builder *sb, Node *node) {
  sb_printf(sb, "^");
  fmt_pat_rec(sb, node);
}

void fmt_pat_end(String_Builder *sb, Node *) {
  sb_printf(sb, "$");
}

void fmt_pat_any(String_Builder *sb, Node *) {
  sb_printf(sb, ".");
}

void fmt_pat_string(String_Builder *sb, Node *node) {
  for (char *c = node->data.string.str; *c != '\0'; c++) {
    if (is_special_char(*c)) {
      sb_printf(sb, "\\%c", *c);
    } else {
      sb_printf(sb, "%c", *c);
    }
  }
}

void fmt_pat_oneof(String_Builder *sb, Node *node) {
  sb_printf(sb, "[%s]", node->data.oneof.chars);
}

void fmt_pat_range(String_Builder *sb, Node *node) {
  sb_printf(sb, "[%c-%c]", node->data.range.from, node->data.range.to);
}

void fmt_pat_some(String_Builder *sb, Node *node) {
  sb_printf(sb, "(");
  fmt_pat_rec(sb, node->data.some.node);
  sb_printf(sb, ")+");
}

void fmt_pat_many(String_Builder *sb, Node *node) {
  sb_printf(sb, "(");
  fmt_pat_rec(sb, node->data.many.node);
  sb_printf(sb, ")*");
}

void fmt_pat_opt(String_Builder *sb, Node *node) {
  sb_printf(sb, "(");
  fmt_pat_rec(sb, node->data.opt.node);
  sb_printf(sb, ")?");
}

void fmt_pat_seq(String_Builder *sb, Node *node) {
  for (auto n = node->data.seq.nodes; *n != nullptr; n++) {
    fmt_pat_rec(sb, *n);
  }
}

void fmt_pat_alt(String_Builder *sb, Node *node) {
  sb_printf(sb, "(");
  bool first = true;
  for (auto n = node->data.alt.nodes; *n != nullptr; n++) {
    if (!first) {
      sb_printf(sb, "|");
    }
    fmt_pat_rec(sb, *n);
    first = false;
  }
  sb_printf(sb, ")");
}

void fmt_pat_not(String_Builder *sb, Node *node) {
  sb_printf(sb, "(?!");
  fmt_pat_rec(sb, node->data.not.node);
  sb_printf(sb, ")");
}

void fmt_pat_try(String_Builder *sb, Node *node) {
  sb_printf(sb, "(?=");
  fmt_pat_rec(sb, node->data.try.node);
  sb_printf(sb, ")");
}

void fmt_pat_capture(String_Builder *sb, Node *node) {
  fmt_pat_rec(sb, node->data.capture.node);
}

void fmt_pat_rec(String_Builder *sb, Node *node) {
  switch (node->type) {
    case NODE_END:
      return fmt_pat_end(sb, node);
    case NODE_ANY:
      return fmt_pat_any(sb, node);
    case NODE_STRING:
      return fmt_pat_string(sb, node);
    case NODE_ONEOF:
      return fmt_pat_oneof(sb, node);
    case NODE_RANGE:
      return fmt_pat_range(sb, node);
    case NODE_SOME:
      return fmt_pat_some(sb, node);
    case NODE_MANY:
      return fmt_pat_many(sb, node);
    case NODE_OPT:
      return fmt_pat_opt(sb, node);
    case NODE_SEQ:
      return fmt_pat_seq(sb, node);
    case NODE_ALT:
      return fmt_pat_alt(sb, node);
    case NODE_NOT:
      return fmt_pat_not(sb, node);
    case NODE_TRY:
      return fmt_pat_try(sb, node);
    case NODE_CAPTURE:
      return fmt_pat_capture(sb, node);
    default:
      assert(0 && "Unknown node type");
  }
}
