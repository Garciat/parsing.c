# parsing.c

A collection of experiments in parser combinators implemented in C (with `-std=c23`).

## Features: rex.c

- Implements regex-like parser combinators for text parsing.
  - Uses macros to define parsers in a declarative DSL style.
  - Each macro expands into address of compound literals:
    - `&(Parser){ ... }`
- Performs no allocations or state mutations during parsing.
- Parser result structure inspired by Haskell's Parsec library.
  - Uses a four-state result model: consumed/empty × ok/error.
  - This distinction allows for backtracking and lookahead.
- The parser state contains a 'fork stack':
  - A parser is pushed onto the stack when a forking decision is made.
  - This is used for smart error reporting.

```c
// - Primitive parsers
// Matches the end of input
#define END()
// Matches any single character
#define ANY()
// Matches a specific character sequence
#define STR(s)
// Matches one of the specified characters
#define ONEOF(chars)
// Matches a character range
#define RANGE(from, to)
// - Combinators
// Matches one or more repetitions
#define SOME(n)
// Matches zero or more repetitions
#define MANY(n)
// Matches an optional element
#define OPT(n)
// Matches a sequence of parsers
#define SEQ(...)
// Matches one of several alternatives
#define ALT(...)
// Matches if the inner parser fails
#define NOT(n)
// Recovers from failure
#define TRY(n)
// - Capture
// Captures the matched input
#define CAPTURE(output, n)
```

Example parser for a simple URL format:

```c
typedef struct {
  String_View domain;
  String_View path;
} URL_Match;

URL_Match *out = ...;

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
```

Example error reporting:

```
Match failure at character 14:

http://example!/path
              ^
Expected:
- end of input
- '-'
- '.'
- '/'
- range 'a'-'z'
- range 'A'-'Z'
- range '0'-'9'
```

## Features: pe.c

- Implements parser combinators for parsing structured binary data.
- Similar overall approach as `rex.c`.
  - However, additonally defines output combinators to write parsed data directly into structures.
    - Apparently this is similar to [Pickler Combinators](https://www.microsoft.com/en-us/research/wp-content/uploads/2004/01/picklercombinators.pdf).
- No allocations, no mutations.

```c
// - Output combinators
// Enters a context where we output to 'd'
#define INTO(d, p)
// Advances the output pointer by 's' if parsing 'p' succeeded
#define STRIDE(s, p)
// Enters a context where we output with an offset 'o'
#define OFFSET(o, p)
// Reads the parsed value of 'p' into the current output location
#define READ(p)

// - Primitive parsers
// Skips 'n' bytes
#define SKIP(n)
// Reads 'n' bytes
#define BYTES(n)
// Reads unsigned integers in little-endian or big-endian format
#define U2_LE()
#define U2_BE()
#define U4_LE()
#define U4_BE()
#define U8_LE()
#define U8_BE()
// Checks that 'p' produces the specified constant value
#define CONST_U2(value, p)
#define CONST_U4(value, p)
#define CONST_U8(value, p)

// - Combinators
// Matches a sequence of parsers
#define SEQ(...)
// Matches one of several alternatives
#define ALT(...)
// Matches 'p' repeated 'n' times
#define REPEAT(n, p)

// - Helpers
#define READ_VALUE(d, p) READ(INTO(d, p))
#define READ_FIELD(t, f, p) READ(offsetof(t, f), p)
#define INTO_ARRAY(a, n, p) INTO(a, REPEAT(n, STRIDE(sizeof(*(a)), p)))
```

Example parser for an array of structures:

```c
Image_Data_Directory data_directories[16] = {0};

auto parser = INTO_ARRAY(
  data_directories,
  data_directories_count,
  SEQ(
    READ_FIELD(Image_Data_Directory, virtual_address, U4_LE()),
    READ_FIELD(Image_Data_Directory, size, U4_LE())
  )
);
```

The file `pe.c` itself includes a (partial) parser of the PE (Portable Executable) file format used in Windows and .NET CLR executables. (Inspired by [this stream](https://www.youtube.com/watch?v=D1j7_0oplbk).)

## Build & Test

Compile and run the tests for all of the files in the project:

```sh
make test
```
