### Lint C++

`lint.ts` is a simple script that will read `replay.cc`, find the inline scripts, and call eslint on each of them. 


**Get started**
```
bun lint.ts ./replay.cc
# or
npx ts-node lint.ts ./replay.cc
```


**Errors**
Running the script will output these errors which might be legitimate.

```
Script gReplayScript:
 [
  {
    ruleId: 'no-unused-vars',
    severity: 1,
    message: "'logTrace' is defined but never used. Allowed unused vars must match /^_/u.",
    line: 228,
    column: 10,
    nodeType: 'Identifier',
    messageId: 'unusedVar',
    endLine: 228,
    endColumn: 18
  },
  {
    ruleId: 'no-unused-vars',
    severity: 1,
    message: "'isNonNullObject' is defined but never used. Allowed unused vars must match /^_/u.",
    line: 981,
    column: 10,
    nodeType: 'Identifier',
    messageId: 'unusedVar',
    endLine: 981,
    endColumn: 25
  },
...
  {
    ruleId: 'no-undef',
    severity: 2,
    message: "'frameIndex' is not defined.",
    line: 1141,
    column: 29,
    nodeType: 'Identifier',
    messageId: 'undef',
    endLine: 1141,
    endColumn: 39
  },
...
 ]
ESLint: 12 errors, 18 warnings
```