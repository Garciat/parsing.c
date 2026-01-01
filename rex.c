#include <assert.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

typedef struct {
  String_View sv;
  size_t position;
} Match_State;


typedef struct {
  Node *node;
  Match_State state;
} Match_Expect;

void fmt_expect_rec(String_Builder *sb, Match_Expect expect);

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
    default:
      sb_printf(sb, "<complex pattern>");
      return;
  }
}

void print_expect(FILE *stream, Match_Expect expect) {
  String_Builder sb = {0};
  fmt_expect_rec(&sb, expect);
  fprintf(stream, "Expected %s at position %zu\n", sb.items, expect.state.position);
  // show input and a caret
  fprintf(stream, "%.*s\n", (int)expect.state.sv.size, expect.state.sv.data);
  fprintf(stream, "%*s^\n", (int)expect.state.position, "");
  free(sb.items);
}

Match_State state_advance(Match_State state, size_t n) {
  assert(state.position + n <= state.sv.size);
  return (Match_State){ .sv = state.sv, .position = state.position + n };
}

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

  while (true) {
    res = match_rec(node->data.many.node, res.state);
    switch (res.status) {
      case CONSUMED_OK:
      case EMPTY_OK:
        continue;
      case CONSUMED_ERROR:
        return res;
      case EMPTY_ERROR:
        return (Match_Result){ .status = EMPTY_OK, .state = res.state };
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

  for (auto n = node->data.seq.nodes; *n != nullptr; n++) {
    res = match_rec(*n, res.state);
    switch (res.status) {
      case CONSUMED_OK:
      case EMPTY_OK:
        continue;
      case CONSUMED_ERROR:
      case EMPTY_ERROR:
        return res;
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

bool match(Node *pattern, String_View input, Match_Expect *out_expect) {
  auto res = match_rec(pattern, (Match_State){ .sv = input, .position = 0 });
  switch (res.status) {
    case CONSUMED_OK:
    case EMPTY_OK:
      return true;
    case CONSUMED_ERROR:
    case EMPTY_ERROR: {
      if (out_expect != nullptr) {
        *out_expect = (Match_Expect){ .node = res.expected, .state = res.state };
      }
      return false;
    }
  }
}

bool match_cstr(Node *pattern, const char *input) {
  return match(pattern, sv_from_cstr(input), nullptr);
}

typedef struct {
  String_View domain;
  String_View path;
} URL_Match;

bool match_url(const char *input, URL_Match *out, Match_Expect *out_expect) {
  auto domain_char = ALT(
    RANGE('a', 'z'),
    RANGE('A', 'Z'),
    RANGE('0', '9'),
    ONEOF("-.")
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
        SOME(domain_char)
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

void test_core_all() {
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
}

bool match_url_test(const char *input, URL_Match *out) {
  Match_Expect expect;
  bool r = match_url(input, out, &expect);
  if (!r) {
    print_expect(stderr, expect);
  }
  return r;
}

void test_url() {
  URL_Match url;
  assert(match_url_test("http://example.com/path", &url));
  assert(strncmp(url.domain.data, "example.com", url.domain.size) == 0);
  assert(strncmp(url.path.data, "/path", url.path.size) == 0);

  assert(match_url_test("https://sub.domain.org/", &url));
  assert(strncmp(url.domain.data, "sub.domain.org", url.domain.size) == 0);
  assert(strncmp(url.path.data, "/", url.path.size) == 0);

  assert(match_url_test("http://example./path", &url));

  assert(!match_url_test("ftp://example.com/path", &url));
}

int main() {
  test_core_all();
  test_url();
  return 0;
}
