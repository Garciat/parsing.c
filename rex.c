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

void sb_undo_char(String_Builder *sb, char c) {
  if (sb->count > 0 && sb->items[sb->count - 1] == c) {
    sb->count--;
    sb->items[sb->count] = '\0';
  }
}

// ==============================================================
// # Node Definitions
// ==============================================================

typedef struct Node {
  enum {
    // Primitives
    NODE_END,
    NODE_ANY,
    NODE_STRING,
    NODE_ONEOF,
    NODE_RANGE,
    // Combinators
    NODE_SOME,
    NODE_MANY,
    NODE_OPT,
    NODE_SEQ,
    NODE_ALT,
    NODE_NOT,
    NODE_TRY,
    // Actions
    NODE_CAPTURE,
  } type;

  union {
    // Primitives
    struct { } end;
    struct { } any;
    struct { char *str; } string;
    struct { char *chars; } oneof;
    struct { char from, to; } range;
    // Combinators
    struct { struct Node *node; } some;
    struct { struct Node *node; } many;
    struct { struct Node *node; } opt;
    struct { struct Node **nodes; } seq;
    struct { struct Node **nodes; } alt;
    struct { struct Node *node; } not;
    struct { struct Node *node; } try;
    // Actions
    struct { struct Node *node; String_View *output; } capture;
  };
} Node;

#define END()              (&(Node){ .type = NODE_END }) 
#define ANY()              (&(Node){ .type = NODE_ANY })
#define STR(s)             (&(Node){ .type = NODE_STRING, .string = { s } })
#define ONEOF(chars)       (&(Node){ .type = NODE_ONEOF, .oneof = { chars } })
#define RANGE(from, to)    (&(Node){ .type = NODE_RANGE, .range = { from, to } })
#define SOME(n)            (&(Node){ .type = NODE_SOME, .some = { n } })
#define MANY(n)            (&(Node){ .type = NODE_MANY, .many = { n } })
#define OPT(n)             (&(Node){ .type = NODE_OPT, .opt = { n } })
#define SEQ(...)           (&(Node){ .type = NODE_SEQ, .seq = { (Node*[]){ __VA_ARGS__, nullptr } } })
#define ALT(...)           (&(Node){ .type = NODE_ALT, .alt = { (Node*[]){ __VA_ARGS__, nullptr } } })
#define NOT(n)             (&(Node){ .type = NODE_NOT, .not = { n } })
#define TRY(n)             (&(Node){ .type = NODE_TRY, .try = { n } })
#define CAPTURE(output, n) (&(Node){ .type = NODE_CAPTURE, .capture = { n, output } })

// ==============================================================
// # Matching Types
// ==============================================================

#define FORK_STACK_CAPACITY 8

typedef struct {
  Node *nodes[FORK_STACK_CAPACITY];
} Fork_Stack;

Fork_Stack fork_stack_push(Fork_Stack stack, Node *node) {
  // find last empty slot; do nothing if full
  for (size_t i = 0; i < FORK_STACK_CAPACITY; i++) {
    if (stack.nodes[i] == nullptr) {
      stack.nodes[i] = node;
      break;
    }
  }
  return stack;
}

typedef struct {
  String_View sv;
  size_t position;
  Fork_Stack fork_stack;
} Match_State;

Match_State state_from_sv(String_View sv) {
  return (Match_State){ .sv = sv, .position = 0 };
}

Match_State state_advance(Match_State state, size_t n) {
  assert(state.position + n <= state.sv.size);
  return (Match_State){ .sv = state.sv, .position = state.position + n };
}

Match_State state_fork(Match_State state, Node *node) {
  return (Match_State){
    .sv = state.sv,
    .position = state.position,
    .fork_stack = fork_stack_push(state.fork_stack, node)
  };
}

typedef struct {
  enum {
    CONSUMED_OK,
    CONSUMED_ERROR,
    EMPTY_OK,
    EMPTY_ERROR
  } status;
  Match_State state;
  union {
    struct { Node *expected; } err;
  };
} Match_Result;

Match_Result result_ok_empty(Match_State state) {
  return (Match_Result){ .status = EMPTY_OK, .state = state };
}

Match_Result result_ok_consumed(Match_State state) {
  return (Match_Result){ .status = CONSUMED_OK, .state = state };
}

Match_Result result_err_empty(Match_State state, Node *expected) {
  return (Match_Result){ .status = EMPTY_ERROR, .state = state, .err = { .expected = expected } };
}

Match_Result result_err_consumed(Match_State state, Node *expected) {
  return (Match_Result){ .status = CONSUMED_ERROR, .state = state, .err = { .expected = expected } };
}

void fmt_result_err(String_Builder *sb, Match_Result result);

// =============================================================
// # Matching Functions
// ==============================================================

Match_Result match_rec(Match_State state, Node *node);

Match_Result match_end(Match_State state, Node *node) {
  assert(node->type == NODE_END);
  if (state.position == state.sv.size) {
    return result_ok_empty(state);
  }
  return result_err_empty(state, node);
}

Match_Result match_any(Match_State state, Node *node) {
  assert(node->type == NODE_ANY);
  if (state.position < state.sv.size) {
    return result_ok_consumed(state_advance(state, 1));
  }
  return result_err_empty(state, node);
}

// Consumes prefix on failure
Match_Result match_string(Match_State state, Node *node) {
  assert(node->type == NODE_STRING);
  assert(node->string.str != nullptr);

  size_t i = 0;
  for (; node->string.str[i] && state.position + i < state.sv.size; i++) {
    if (state.sv.data[state.position + i] != node->string.str[i]) {
      break;
    }
  }

  if (node->string.str[i] == '\0') {
    return result_ok_consumed(state_advance(state, i));
  } else if (i == 0) {
    return result_err_empty(state, node);
  } else {
    return result_err_consumed(state_advance(state, i), node);
  }
}

Match_Result match_oneof(Match_State state, Node *node) {
  assert(node->type == NODE_ONEOF);
  assert(node->oneof.chars != nullptr);

  if (state.position < state.sv.size) {
    for (char *c = node->oneof.chars; *c != '\0'; c++) {
      if (state.sv.data[state.position] == *c) {
        return (Match_Result){ .status = CONSUMED_OK, .state = state_advance(state, 1) };
      }
    }
  }

  return result_err_empty(state, node);
}

Match_Result match_range(Match_State state, Node *node) {
  assert(node->type == NODE_RANGE);
  assert(node->range.from <= node->range.to);

  if (state.position < state.sv.size &&
      state.sv.data[state.position] >= node->range.from &&
      state.sv.data[state.position] <= node->range.to) {
    return result_ok_consumed(state_advance(state, 1));
  }
  
  return result_err_empty(state, node);
}

Match_Result match_many(Match_State state, Node *node) {
  assert(node->type == NODE_MANY);
  assert(node->many.node != nullptr);

  auto current_state = state;
  bool consumed = false;

  while (true) {
    auto res = match_rec(current_state, node->many.node);
    switch (res.status) {
      case CONSUMED_OK:
        current_state = res.state;
        consumed = true;
        continue;
      case EMPTY_OK:
        current_state = res.state;
        continue;
      case CONSUMED_ERROR:
        return res;
      case EMPTY_ERROR:
        if (consumed) {
          return result_ok_consumed(state_fork(res.state, node));
        } else {
          return result_ok_empty(state_fork(res.state, node));
        }
    }
  }
}

Match_Result match_some(Match_State state, Node *node) {
  assert(node->type == NODE_SOME);
  assert(node->some.node != nullptr);

  auto res = match_rec(state, node->some.node);
  switch (res.status) {
    case CONSUMED_OK:
    case EMPTY_OK:
      return match_many(res.state, MANY(node->some.node));
    case CONSUMED_ERROR:
    case EMPTY_ERROR:
      return res;
  }
}

Match_Result match_opt(Match_State state, Node *node) {
  assert(node->type == NODE_OPT);
  assert(node->opt.node != nullptr);

  auto res = match_rec(state, node->opt.node);
  switch (res.status) {
    case CONSUMED_OK:
    case EMPTY_OK:
    case CONSUMED_ERROR:
      return res;
    case EMPTY_ERROR:
      return result_ok_empty(state_fork(state, node));
  }
}

Match_Result match_seq(Match_State state, Node *node) {
  assert(node->type == NODE_SEQ);
  assert(node->seq.nodes != nullptr);

  auto current_state = state;
  bool consumed = false;

  for (auto n = node->seq.nodes; *n != nullptr; n++) {
    auto res = match_rec(current_state, *n);
    switch (res.status) {
      case CONSUMED_OK:
        current_state = res.state;
        consumed = true;
        continue;
      case EMPTY_OK:
        current_state = res.state;
        continue;
      case CONSUMED_ERROR:
        return res;
      case EMPTY_ERROR:
        if (consumed) {
          return result_err_consumed(res.state, res.err.expected);
        } else {
          return res;
        }
    }
  }

  if (consumed) {
    return result_ok_consumed(current_state);
  } else {
    return result_ok_empty(current_state);
  }
}

Match_Result match_alt(Match_State state, Node *node) {
  assert(node->type == NODE_ALT);
  assert(node->alt.nodes != nullptr);

  auto current_state = state;

  for (auto n = node->alt.nodes; *n != nullptr; n++) {
    auto res = match_rec(current_state, *n);
    switch (res.status) {
      case CONSUMED_OK:
      case EMPTY_OK:
        return res;
      case CONSUMED_ERROR:
        return res;
      case EMPTY_ERROR:
        current_state = state_fork(current_state, node);
        continue;
    }
  }

  return result_err_empty(current_state, node);
}

Match_Result match_not(Match_State state, Node *node) {
  assert(node->type == NODE_NOT);
  assert(node->not.node != nullptr);

  auto res = match_rec(state, node->not.node);
  switch (res.status) {
    case CONSUMED_OK:
      return result_err_consumed(state, node);
    case EMPTY_OK:
      return result_err_empty(state, node);
    case CONSUMED_ERROR:
      return result_ok_consumed(state);
    case EMPTY_ERROR:
      return result_ok_empty(state);
  }
}

Match_Result match_try(Match_State state, Node *node) {
  assert(node->type == NODE_TRY);
  assert(node->try.node != nullptr);

  auto res = match_rec(state, node->try.node);
  switch (res.status) {
    case CONSUMED_OK:
    case EMPTY_OK:
      return res;
    case CONSUMED_ERROR:
    case EMPTY_ERROR:
      return result_err_empty(state, res.err.expected);
  }
}

Match_Result match_capture(Match_State state, Node *node) {
  assert(node->type == NODE_CAPTURE);
  assert(node->capture.node != nullptr);
  assert(node->capture.output != nullptr);

  auto res = match_rec(state, node->capture.node);
  switch (res.status) {
    case CONSUMED_OK:
    case EMPTY_OK:
      *(node->capture.output) = (String_View){
        .data = state.sv.data + state.position,
        .size = res.state.position - state.position
      };
      return res;
    case CONSUMED_ERROR:
    case EMPTY_ERROR:
      return res;
  }
}

Match_Result match_rec(Match_State state, Node *node) {
  switch (node->type) {
    case NODE_END:
      return match_end(state, node);
    case NODE_ANY:
      return match_any(state, node);
    case NODE_STRING:
      return match_string(state, node);
    case NODE_ONEOF:
      return match_oneof(state, node);
    case NODE_RANGE:
      return match_range(state, node);
    case NODE_SOME:
      return match_some(state, node);
    case NODE_MANY:
      return match_many(state, node);
    case NODE_OPT:
      return match_opt(state, node);
    case NODE_SEQ:
      return match_seq(state, node);
    case NODE_ALT:
      return match_alt(state, node);
    case NODE_NOT:
      return match_not(state, node);
    case NODE_TRY:
      return match_try(state, node);
    case NODE_CAPTURE:
      return match_capture(state, node);
    default:
      assert(0 && "Unknown node type");
  }
}

bool match(Node *pattern, String_View input, String_Builder *out_expect) {
  auto res = match_rec(state_from_sv(input), pattern);
  switch (res.status) {
    case CONSUMED_OK:
    case EMPTY_OK:
      return true;
    case CONSUMED_ERROR:
    case EMPTY_ERROR: {
      if (out_expect != nullptr) {
        fmt_result_err(out_expect, res);
      }
      return false;
    }
  }
}

bool match_cstr(Node *pattern, const char *input) {
  return match(pattern, sv_from_cstr(input), nullptr);
}

void fmt_pat(String_Builder *sb, Node *node);

// useful for debug watches
char *fmt_pat_alloc(Node *node) {
  String_Builder sb = {0};
  fmt_pat(&sb, node);
  sb_printf(&sb, "\0");
  return sb.items;
}

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

void test_all();
void test_core();
void test_url();
void demo();

int main() {
  test_all();
  demo();
  return 0;
}

void test_all() {
  printf("Running all tests...\n");

  test_core();
  printf("All core tests passed.\n");

  test_url();
  printf("All URL tests passed.\n");
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

void demo() {
  printf("==============================================================\n");
  printf("Demo debug output for URL matching failure:\n\n");

  URL_Match url;
  match_url_test("http://example!/path", &url);
}

// ==============================================================
// # Debug Printing
// ==============================================================

#define EXPECT_LIMIT_CHARS 256
#define EXPECT_LIMIT_ONEOFS 16
#define EXPECT_LIMIT_RANGES 16
#define EXPECT_LIMIT_STRINGS 16
#define EXPECT_CHAR_EOF '\0'
#define EXPECT_CHAR_ANY '\1'

typedef struct {
  bool chars[EXPECT_LIMIT_CHARS];
  char *oneofs[EXPECT_LIMIT_ONEOFS];
  size_t oneofs_count;
  struct Expect_Range { char from, to; } ranges[EXPECT_LIMIT_RANGES];
  size_t ranges_count;
  const char *strings[EXPECT_LIMIT_STRINGS];
  size_t strings_count;
} Expect_Set;

Expect_Set expect_set_union(Expect_Set a, Expect_Set b) {
  Expect_Set result = a;

  for (size_t i = 0; i < EXPECT_LIMIT_CHARS; i++) {
    result.chars[i] = a.chars[i] || b.chars[i];
  }

  for (size_t i = 0; i < b.oneofs_count; i++) {
    // dedupe
    for (size_t j = 0; j < result.oneofs_count; j++) {
      if (strcmp(result.oneofs[j], b.oneofs[i]) == 0) {
        goto skip_oneof;
      }
    }
    if (result.oneofs_count < EXPECT_LIMIT_ONEOFS) {
      result.oneofs[result.oneofs_count++] = b.oneofs[i];
    }
skip_oneof:
  }

  for (size_t i = 0; i < b.ranges_count; i++) {
    // dedupe
    for (size_t j = 0; j < result.ranges_count; j++) {
      if (result.ranges[j].from == b.ranges[i].from &&
          result.ranges[j].to == b.ranges[i].to) {
        goto skip_range;
      }
    }
    if (result.ranges_count < EXPECT_LIMIT_RANGES) {
      result.ranges[result.ranges_count++] = b.ranges[i];
    }
skip_range:
  }

  for (size_t i = 0; i < b.strings_count; i++) {
    // dedupe
    for (size_t j = 0; j < result.strings_count; j++) {
      if (strcmp(result.strings[j], b.strings[i]) == 0) {
        goto skip_string;
      }
    }
    if (result.strings_count < EXPECT_LIMIT_STRINGS) {
      result.strings[result.strings_count++] = b.strings[i];
    }
skip_string:
  }

  return result;
}

Expect_Set expect_set_of_char(char c) {
  Expect_Set set = {0};
  set.chars[(unsigned char)c] = true;
  return set;
}

Expect_Set expect_set_of_string(const char *str) {
  if (strlen(str) == 1) {
    return expect_set_of_char(str[0]);
  }
  Expect_Set set = {0};
  set.strings[set.strings_count++] = str;
  return set;
}

Expect_Set expect_set_of_oneof(const char *chars) {
  if (strlen(chars) == 1) {
    return expect_set_of_char(chars[0]);
  }
  Expect_Set set = {0};
  set.oneofs[set.oneofs_count++] = (char *)chars;
  return set;
}

Expect_Set expect_set_of_range(char from, char to) {
  Expect_Set set = {0};
  set.ranges[set.ranges_count++] = (struct Expect_Range){ from, to };
  return set;
}

Expect_Set expect_set_negate(Expect_Set set) {
  return set; // TODO
}

void expect_set_fmt(Expect_Set set, String_Builder *sb) {
  for (size_t i = 0; i < EXPECT_LIMIT_CHARS; i++) {
    if (set.chars[i]) {
      sb_printf(sb, "- ");
      if (i == EXPECT_CHAR_EOF) {
        sb_printf(sb, "end of input");
      } else if (i == EXPECT_CHAR_ANY) {
        sb_printf(sb, "any character");
      } else {
        sb_printf(sb, "'%c'", (char)i);
      }
      sb_printf(sb, "\n");
    }
  }

  for (size_t i = 0; i < set.oneofs_count; i++) {
    sb_printf(sb, "- one of [%s]\n", set.oneofs[i]);
  }

  for (size_t i = 0; i < set.ranges_count; i++) {
    sb_printf(sb, "- range '%c'-'%c'\n", set.ranges[i].from, set.ranges[i].to);
  }

  for (size_t i = 0; i < set.strings_count; i++) {
    sb_printf(sb, "- string \"%s\"\n", set.strings[i]);
  }

  sb_undo_char(sb, '\n');
}

Expect_Set pat_expect_rec(Node *node);

void fmt_result_err(String_Builder *sb, Match_Result result) {
  assert(result.status == CONSUMED_ERROR || result.status == EMPTY_ERROR);

  sb_printf(sb, "Match failure at character %zu:\n\n", result.state.position);

  sb_printf(sb, "%.*s\n", (int)result.state.sv.size, result.state.sv.data);
  sb_printf(sb, "%*s^\n", (int)result.state.position, "");

  Expect_Set expect = pat_expect_rec(result.err.expected);

  for (size_t i = 0; i < FORK_STACK_CAPACITY; i++) {
    if (result.state.fork_stack.nodes[i] == nullptr) break;
    expect = expect_set_union(
      expect,
      pat_expect_rec(result.state.fork_stack.nodes[i])
    );
  }

  sb_printf(sb, "Expected:\n");
  expect_set_fmt(expect, sb);
  sb_printf(sb, "\n");
}

Expect_Set pat_expect_end(Node *) {
  return expect_set_of_char(EXPECT_CHAR_EOF);
}

Expect_Set pat_expect_any(Node *) {
  return expect_set_of_char(EXPECT_CHAR_ANY);
}

Expect_Set pat_expect_string(Node *node) {
  return expect_set_of_string(node->string.str);
}

Expect_Set pat_expect_oneof(Node *node) {
  return expect_set_of_oneof(node->oneof.chars);
}

Expect_Set pat_expect_range(Node *node) {
  return expect_set_of_range(node->range.from, node->range.to);
}

Expect_Set pat_expect_many(Node *node) {
  return pat_expect_rec(node->many.node);
}

Expect_Set pat_expect_some(Node *node) {
  return pat_expect_rec(node->some.node);
}

Expect_Set pat_expect_opt(Node *node) {
  return pat_expect_rec(node->opt.node);
}

Expect_Set pat_expect_seq(Node *node) {
  assert(node->seq.nodes != nullptr);
  return pat_expect_rec(node->seq.nodes[0]);
}

Expect_Set pat_expect_alt(Node *node) {
  Expect_Set set = {0};
  for (auto n = node->alt.nodes; *n != nullptr; n++) {
    set = expect_set_union(set, pat_expect_rec(*n));
  }
  return set;
}

Expect_Set pat_expect_not(Node *node) {
  return expect_set_negate(pat_expect_rec(node->not.node));
}

Expect_Set pat_expect_try(Node *node) {
  return pat_expect_rec(node->try.node);
}

Expect_Set pat_expect_capture(Node *node) {
  return pat_expect_rec(node->capture.node);
}

Expect_Set pat_expect_rec(Node *node) {
  switch (node->type) {
    case NODE_END:
      return pat_expect_end(node);
    case NODE_ANY:
      return pat_expect_any(node);
    case NODE_STRING:
      return pat_expect_string(node);
    case NODE_ONEOF:
      return pat_expect_oneof(node);
    case NODE_RANGE:
      return pat_expect_range(node);
    case NODE_SOME:
      return pat_expect_some(node);
    case NODE_MANY:
      return pat_expect_many(node);
    case NODE_OPT:
      return pat_expect_opt(node);
    case NODE_SEQ:
      return pat_expect_seq(node);
    case NODE_ALT:
      return pat_expect_alt(node);
    case NODE_NOT:
      return pat_expect_not(node);
    case NODE_TRY:
      return pat_expect_try(node);
    case NODE_CAPTURE:
      return pat_expect_capture(node);
  }
  assert(0 && "Unknown node type");
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
  fmt_pat_rec(sb, node);
}

void fmt_pat_end(String_Builder *sb, Node *) {
  sb_printf(sb, "$");
}

void fmt_pat_any(String_Builder *sb, Node *) {
  sb_printf(sb, ".");
}

void fmt_pat_string(String_Builder *sb, Node *node) {
  for (char *c = node->string.str; *c != '\0'; c++) {
    if (is_special_char(*c)) {
      sb_printf(sb, "\\%c", *c);
    } else {
      sb_printf(sb, "%c", *c);
    }
  }
}

void fmt_pat_oneof(String_Builder *sb, Node *node) {
  sb_printf(sb, "[%s]", node->oneof.chars);
}

void fmt_pat_range(String_Builder *sb, Node *node) {
  sb_printf(sb, "[%c-%c]", node->range.from, node->range.to);
}

void fmt_pat_some(String_Builder *sb, Node *node) {
  sb_printf(sb, "(");
  fmt_pat_rec(sb, node->some.node);
  sb_printf(sb, ")+");
}

void fmt_pat_many(String_Builder *sb, Node *node) {
  sb_printf(sb, "(");
  fmt_pat_rec(sb, node->many.node);
  sb_printf(sb, ")*");
}

void fmt_pat_opt(String_Builder *sb, Node *node) {
  sb_printf(sb, "(");
  fmt_pat_rec(sb, node->opt.node);
  sb_printf(sb, ")?");
}

void fmt_pat_seq(String_Builder *sb, Node *node) {
  for (auto n = node->seq.nodes; *n != nullptr; n++) {
    fmt_pat_rec(sb, *n);
  }
}

bool fmt_pat_alt_ranges(String_Builder *sb, Node *node) {
  for (auto n = node->alt.nodes; *n != nullptr; n++) {
    if ((*n)->type != NODE_RANGE && (*n)->type != NODE_ONEOF) {
      return false;
    }
  }

  sb_printf(sb, "[");
  bool first = true;
  for (auto n = node->alt.nodes; *n != nullptr; n++) {
    if (!first) {
      sb_printf(sb, "");
    }
    switch ((*n)->type) {
      case NODE_RANGE:
        sb_printf(sb, "%c-%c", (*n)->range.from, (*n)->range.to);
        break;
      case NODE_ONEOF:
        for (char *c = (*n)->oneof.chars; *c != '\0'; c++) {
          sb_printf(sb, "%c", *c);
        }
        break;
      default:
        assert(0 && "Unexpected node type in alt ranges");
    }
    first = false;
  }
  sb_printf(sb, "]");

  return true;
}

void fmt_pat_alt(String_Builder *sb, Node *node) {
  if (fmt_pat_alt_ranges(sb, node)) {
    return;
  }

  sb_printf(sb, "(");
  bool first = true;
  for (auto n = node->alt.nodes; *n != nullptr; n++) {
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
  fmt_pat_rec(sb, node->not.node);
  sb_printf(sb, ")");
}

void fmt_pat_try(String_Builder *sb, Node *node) {
  sb_printf(sb, "(?=");
  fmt_pat_rec(sb, node->try.node);
  sb_printf(sb, ")");
}

void fmt_pat_capture(String_Builder *sb, Node *node) {
  fmt_pat_rec(sb, node->capture.node);
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
  }
  assert(0 && "Unknown node type");
}
