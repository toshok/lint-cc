### Lint C++

`lint.ts` is a simple script that will read `replay.cc`, find the inline scripts, and call eslint on each of them. 


**Get started**
```
bun lint.ts
```

**Errors**
Running the script will output these errors which might be legitimate.

```
[
  {
    ruleId: "no-undef",
    severity: 2,
    message: "'frames' is not defined.",
    line: 976,
    column: 66,
    nodeType: "Identifier",
    messageId: "undef",
    endLine: 976,
    endColumn: 72
  }, {
    ruleId: "no-undef",
    severity: 2,
    message: "'frameIndex' is not defined.",
    line: 979,
    column: 29,
    nodeType: "Identifier",
    messageId: "undef",
    endLine: 979,
    endColumn: 39
  }, {
    ruleId: "no-undef",
    severity: 2,
    message: "'getObjectIdRaw' is not defined.",
    line: 1511,
    column: 13,
    nodeType: "Identifier",
    messageId: "undef",
    endLine: 1511,
    endColumn: 27
  }, {
    ruleId: "no-undef",
    severity: 2,
    message: "'styleInfo' is not defined.",
    line: 2054,
    column: 5,
    nodeType: "Identifier",
    messageId: "undef",
    endLine: 2054,
    endColumn: 14
  }, {
    ruleId: "no-undef",
    severity: 2,
    message: "'styleInfo' is not defined.",
    line: 2055,
    column: 25,
    nodeType: "Identifier",
    messageId: "undef",
    endLine: 2055,
    endColumn: 34
  }, {
    ruleId: "no-undef",
    severity: 2,
    message: "'styleInfo' is not defined.",
    line: 2057,
    column: 15,
    nodeType: "Identifier",
    messageId: "undef",
    endLine: 2057,
    endColumn: 24
  }, {
    ruleId: "no-undef",
    severity: 2,
    message: "'styleInfo' is not defined.",
    line: 2058,
    column: 16,
    nodeType: "Identifier",
    messageId: "undef",
    endLine: 2058,
    endColumn: 25
  }, {
    ruleId: "no-undef",
    severity: 2,
    message: "'styleInfo' is not defined.",
    line: 2058,
    column: 43,
    nodeType: "Identifier",
    messageId: "undef",
    endLine: 2058,
    endColumn: 52
  }
]
ESLint issue
ESLint issue
```