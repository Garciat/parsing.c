#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

typedef struct {
  const char *data;
  size_t size;
} String_View;

String_View sv_empty() {
  return (String_View){ .data=nullptr, .size=0 };
}

bool sv_is_empty(String_View sv) {
  return sv.size == 0;
}

String_View sv_from_cstr(const char *cstr) {
  return (String_View){ .data=cstr, .size=strlen(cstr) };
}

typedef struct Node {
  enum { 
    NODE_STRING,
    NODE_ONEOF,
    NODE_RANGE,
    NODE_SEQ,
    NODE_SOME,
    NODE_MANY,
    NODE_OPT,
    NODE_ALT,
    NODE_NOT,
    NODE_TRY,

    NODE_CAPTURE,

    NODE_BEGIN,
    NODE_END
  } type;

  union {
    struct { char *str; } string;
    struct { char *chars; } oneof;
    struct { char from, to; } range;
    struct { struct Node **nodes; } seq;
    struct { struct Node *node; } some;
    struct { struct Node *node; } many;
    struct { struct Node *node; } opt;
    struct { struct Node **nodes; } alt;
    struct { struct Node *node; } not;
    struct { struct Node *node; } try;
    struct { struct Node *node; String_View *output; } capture;
    // struct { } begin;
    // struct { } end;
  } data;
} Node;

#define BEGIN()            (&(Node){ .type = NODE_BEGIN })
#define END()              (&(Node){ .type = NODE_END }) 
#define STR(s)             (&(Node){ .type = NODE_STRING, .data.string = { s } })
#define ONEOF(chars)       (&(Node){ .type = NODE_ONEOF, .data.oneof = { chars } })
#define RANGE(from, to)    (&(Node){ .type = NODE_RANGE, .data.range = { from, to } })
#define SEQ(...)           (&(Node){ .type = NODE_SEQ, .data.seq = { (Node**)&(Node*[]){ __VA_ARGS__, nullptr } } })
#define SOME(n)            (&(Node){ .type = NODE_SOME, .data.some = { n } })
#define MANY(n)            (&(Node){ .type = NODE_MANY, .data.many = { n } })
#define OPT(n)             (&(Node){ .type = NODE_OPT, .data.opt = { n } })
#define ALT(...)           (&(Node){ .type = NODE_ALT, .data.alt = { (Node**)&(Node*[]){ __VA_ARGS__, nullptr } } })
#define NOT(n)             (&(Node){ .type = NODE_NOT, .data.not = { n } })
#define TRY(n)             (&(Node){ .type = NODE_TRY, .data.try = { n } })
#define CAPTURE(output, n) (&(Node){ .type = NODE_CAPTURE, .data.capture = { n, output } })

typedef struct {
  String_View sv;
  size_t position;
} Match_State;

Match_State state_advance(Match_State state, size_t n) {
  if (state.position + n > state.sv.size) {
    n = state.sv.size - state.position;
  }
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
} Match_Result;

Match_Result match_rec(Node *node, Match_State state);

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
    return (Match_Result){ .status = EMPTY_ERROR, .state = state };
  } else {
    return (Match_Result){ .status = CONSUMED_ERROR, .state = state_advance(state, i) };
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
  return (Match_Result){ .status = EMPTY_ERROR, .state = state };
}

Match_Result match_range(Node *node, Match_State state) {
  assert(node->data.range.from <= node->data.range.to);

  if (state.position < state.sv.size &&
      state.sv.data[state.position] >= node->data.range.from &&
      state.sv.data[state.position] <= node->data.range.to) {
    return (Match_Result){ .status = CONSUMED_OK, .state = state_advance(state, 1) };
  }
  return (Match_Result){ .status = EMPTY_ERROR, .state = state };
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

  return (Match_Result){ .status = EMPTY_ERROR, .state = state };
}

Match_Result match_not(Node *node, Match_State state) {
  assert(node->data.not.node != nullptr);

  auto res = match_rec(node->data.not.node, state);
  switch (res.status) {
    case CONSUMED_OK:
      return (Match_Result){ .status = CONSUMED_ERROR, .state = state };
    case EMPTY_OK:
      return (Match_Result){ .status = EMPTY_ERROR, .state = state };
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
      return (Match_Result){ .status = EMPTY_ERROR, .state = state };
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

Match_Result match_begin(Node *, Match_State state) {
  if (state.position == 0) {
    return (Match_Result){ .status = EMPTY_OK, .state = state };
  }
  return (Match_Result){ .status = EMPTY_ERROR, .state = state };
}

Match_Result match_end(Node *, Match_State state) {
  if (state.position == state.sv.size) {
    return (Match_Result){ .status = EMPTY_OK, .state = state };
  }
  return (Match_Result){ .status = EMPTY_ERROR, .state = state };
}

Match_Result match_rec(Node *node, Match_State state) {
  switch (node->type) {
    case NODE_STRING:
      return match_string(node, state);
    case NODE_ONEOF:
      return match_oneof(node, state);
    case NODE_RANGE:
      return match_range(node, state);
    case NODE_SEQ:
      return match_seq(node, state);
    case NODE_SOME:
      return match_some(node, state);
    case NODE_MANY:
      return match_many(node, state);
    case NODE_OPT:
      return match_opt(node, state);
    case NODE_ALT:
      return match_alt(node, state);
    case NODE_NOT:
      return match_not(node, state);
    case NODE_TRY:
      return match_try(node, state);
    case NODE_CAPTURE:
      return match_capture(node, state);
    case NODE_BEGIN:
      return match_begin(node, state);
    case NODE_END:
      return match_end(node, state);
    default:
      assert(0 && "Unknown node type");
  }
}

bool match(Node *pattern, String_View input) {
  auto res = match_rec(pattern, (Match_State){ .sv = input, .position = 0 });
  switch (res.status) {
    case CONSUMED_OK:
    case EMPTY_OK:
      return true;
    case CONSUMED_ERROR:
    case EMPTY_ERROR:
      return false;
  }
}

bool match_cstr(Node *pattern, const char *input) {
  return match(pattern, sv_from_cstr(input));
}

typedef struct {
  String_View domain;
  String_View path;
} URL_Match;

bool match_url(const char *input, URL_Match *out) {
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
    BEGIN(),
    STR("http"),
    OPT(STR("s")),
    STR("://"),
    CAPTURE(
      &out->domain,
      SEQ(
        OPT(SEQ(SOME(domain_char), STR("."))),
        SOME(domain_char),
        ALT(
          STR(".com"),
          STR(".org"),
          STR(".net")
        )
      )
    ),
    CAPTURE(
      &out->path,
      MANY(SEQ(STR("/"), MANY(path_char)))
    ),
    END()
  );

  return match(pat, sv_from_cstr(input));
}

int main() {
  assert(match_cstr(STR("hello"), "hello"));
  assert(!match_cstr(STR("hello"), "hell"));
  assert(match_cstr(SEQ(STR("he"), STR("llo")), "hello"));
  assert(match_cstr(SOME(RANGE('a', 'z')), "abcxyz"));
  assert(!match_cstr(SOME(RANGE('a', 'z')), "123"));
  assert(match_cstr(OPT(STR("hello")), "hello"));
  assert(match_cstr(OPT(STR("hello")), ""));
  assert(match_cstr(ALT(STR("cat"), STR("dog")), "dog"));
  assert(!match_cstr(ALT(STR("cat"), STR("dog")), "mouse"));
  assert(match_cstr(SEQ(BEGIN(), STR("start"), END()), "start"));
  assert(!match_cstr(SEQ(BEGIN(), STR("start"), END()), "notstart"));
  assert(match_cstr(NOT(STR("fail")), "success"));
  assert(!match_cstr(NOT(STR("fail")), "fail"));

  assert(!match_cstr(ALT(STR("help"), STR("hello")), "hello"));
  assert(match_cstr(ALT(TRY(STR("help")), STR("hello")), "hello"));

  {
    URL_Match url;
    assert(match_url("https://www.example.com/path/to/resource", &url));
    assert(strncmp(url.domain.data, "www.example.com", url.domain.size) == 0);
    assert(strncmp(url.path.data, "/path/to/resource", url.path.size) == 0);
  }

  return 0;
}
