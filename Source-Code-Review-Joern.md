# Source-Code & Binary Vulnerability Research with Joern (CPG + Data-Flow)

A practitioner methodology for finding zero-days by querying a **Code Property Graph**
instead of grepping. Technique popularized by Prabhu (Null:404) and built on
[Joern](https://joern.io).

## Core idea

Joern parses source or a binary into a **Code Property Graph (CPG)** — AST + control-flow
graph + program-dependence graph in one queryable structure — then you run **source→sink
data-flow (taint) queries** over it. The mental model: pour colored liquid in at the entry
points and see where it leaks. Unlike grep/Semgrep (AST-only, single-file), the CPG tracks
data flow **across functions, modules, and binaries**, which is what surfaces real bugs.
Build is **not required**; Joern parses code that does not compile.

## Tools

```bash
# Joern (engine)
curl -L https://github.com/joernio/joern/releases/latest/download/joern-install.sh | bash
# or: brew install joern

# Firmware / binaries
brew install binwalk               # extract firmware filesystems
# ghidra2cpg ships with Joern (binary -> CPG via Ghidra)
pip install cpggen                 # AppThreat: CPG from source OR binaries, many langs
# https://github.com/AppThreat/joern-lib  -- prebuilt query library
```

## Target selection

1. **Open-source / GPL on GitHub** — GPL forces device firmware source public (e.g. router/car build systems); no hardware purchase needed.
2. **Router / IoT firmware** — download vendor firmware, `binwalk -e firmware.bin` to extract; or buy the device + UART/telnet adapter to dump the binary.
3. **Any app** — Java, JavaScript, C/C++, or a raw binary.

## Step-by-step

**1. Import the target**
```scala
joern
importCode(inputPath="/path/to/src", projectName="target")   // source (build optional)
importCpg("cpg.bin.zip")                                     // binary/firmware CPG
```

**2. Recon — learn the codebase**
```scala
cpg.method.name.l                                       // every method name
cpg.method.name("mg_.*").name.l                         // filter by prefix
cpg.method.filter(_.parameter.size > 4).name.l          // "complex functions" (many args)
cpg.method.filter(_.controlStructure.size > 10).name.l  // many loops/conditions = poorly tested
cpg.method.name("set_request_handler").dump             // decompile/read a function
```
Heuristic: go straight for complex functions and event handlers — the worst-tested code.

**3. Dangerous sinks**
```scala
cpg.call.name("strcpy","strcat","sprintf","gets","memcpy").l   // memory corruption
cpg.call.name("fopen","open").l                                // path traversal / file ops
cpg.call.name("system","exec.*","popen").l                     // command injection
```

**4. Attacker-controlled source**
```scala
def src = cpg.method.name("onTcpServerEvent").parameter        // event input
def src = cpg.call.name("getParameter","getCookie").argument   // web input / cookies
```

**5. The money query — taint source -> sink**
```scala
def sink = cpg.call.name("strcpy").argument
sink.reachableByFlows(src).p        // prints every tainted path source -> sink
```
A printed path means attacker input reaches an unbounded `strcpy` (out-of-bounds write).

**6. Binaries: decompile -> re-import**
Joern's Ghidra plugin decompiles the binary to C; `importCode` that C so strings are
visible and the full query set applies.

## Reusable query patterns

| Bug class | Pattern |
|---|---|
| Memory corruption | `src(event/param)` -> `strcpy/strcat/sprintf/memcpy` via `reachableByFlows` |
| Directory traversal | web input -> `fopen/open` arg built by string concat |
| Unauth file upload | upload sink whose method has **no** auth call on the path |
| Open redirect | redirect sink reachable from user input on routes missing an auth-session call |
| Hardcoded cloud creds | `cpg.call.name("<init>")` constructing a credentials class with literal key args |
| Cloud injection | `src = context` -> `sink = get\|put\|create\|upload\|delete\|execute\|send.*` |

## Gotchas

- **No build needed** — Joern analyzes non-compiling code.
- **Wildcards** — `name("upload.*")`, `name("(?i)strcpy")`; exact names not required.
- **The learning curve is in the queries** — `AppThreat/joern-lib` ships prebuilt source/sink sets per language (Java/Spring, JS, C).
- Automate it: sink-centric slicing + LLM triage turns this manual loop into a pipeline.

## References

- Joern — https://joern.io
- AppThreat joern-lib — https://github.com/AppThreat/joern-lib
- Null:404 talk, "How to find Zero Days using Joern" (Prabhu)

> Authorized targets and responsible disclosure only.
