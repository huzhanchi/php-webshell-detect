# Table of Contents

- [Intro](#intro)
- [Implemented components](#implemented-components)
- [Taint Analysis](#taint-analysis)
   * [Context-Sensitive Types](#context-sensitive-types)
   * [Propagation Categories](#propagation-categories)
   * [Assignment Classification](#assignment-classification)
   * [Detection Process](#detection-process)
   * [Core Solve Algorithm](#core-solve-algorithm)
- [Strategy](#strategy)
   * [Taint Analyze](#taint-analyze)
   * [Flow Definition](#flow-definition)
   * [What Happens with Unmocked Functions](#what-happens-with-unmocked-functions)
   * [Pitfalls to Work around](#pitfalls-to-work-around)
   * [TODO](#todo)


# Intro

A static program analysis technology to detect PHP WebShells. It examines whether a PHP script has external controllable input variables used to deliver dangerous commands. Given the complexity of actual scripts, which may include arrays, classes, and various structural statements, how can we model these in a static context?

Pointer analysis or alias analysis is an important branch of static program analysis, primarily addressing the question of which possible values a variable in a statement might point to without running the program. We supports k-callsite-n and ci (insensitive context).

```php
<?php
shell_exec("/tmp/bd " . $_POST['port'] . " " . $_POST['bind_pass'] . " &");
?>
```

Check Result:

```text
type:normal msg="[%temp2_6=shell_exec(%temp2_17)]$sink:0--->[[]const6_taint,[]merged0_]"
```

Debug mode:
```text
EntryMain::shell_exec($sink)
48 1	%conststring48_1524=
48 2	return %conststring48_1524
EntryMain::main()
2 1	%conststring2_17=/tmp/bd 
2 2	%temp2_30=$_POST[*]
2 3	%temp2_17=%conststring2_17.%temp2_30
2 4	%conststring2_47= 
2 5	%temp2_17=%temp2_17.%conststring2_47
2 6	%temp2_53=$_POST[*]
2 7	%temp2_17=%temp2_17.%temp2_53
2 8	%conststring2_75= &
2 9	%temp2_17=%temp2_17.%conststring2_75
2 10	%temp2_6=shell_exec(%temp2_17)
5 11	%conststring5_183=
5 12	$global_buffer=%conststring5_183
6 13	$_GET=new Array
6 14	$_GET->init()
6 15	$_GET->__destruct()
7 16	%conststring7_210=taint
7 17	$_GET[*]=%conststring7_210
8 18	$_POST=new Array
8 19	$_POST->init()
8 20	$_POST->__destruct()
9 21	%conststring9_244=taint
9 22	$_POST[*]=%conststring9_244
10 23	$_COOKIE=new Array
10 24	$_COOKIE->init()
10 25	$_COOKIE->__destruct()
11 26	%conststring11_282=taint
11 27	$_COOKIE[*]=%conststring11_282
12 28	$_REQUEST=new Array
12 29	$_REQUEST->init()
12 30	$_REQUEST->__destruct()
13 31	%conststring13_322=taint
13 32	$_REQUEST[*]=%conststring13_322
14 33	$_SERVER=new Array
14 34	$_SERVER->init()
14 35	$_SERVER->__destruct()
15 36	%conststring15_360=taint
15 37	$_SERVER[*]=%conststring15_360
57 38	%conststring57_1898=taint
57 39	return %conststring57_1898
time="2024-02-16T14:49:50+07:00" level=debug msg="[%temp2_6=shell_exec(%temp2_17)]$sink:0--->[[]const6_taint,[]merged0_]"
```

# Implemented components
- context

  Context sensitivity is crucial, currently implemented as k-callsite-n, with n defaulting to 2.

- heap

  Simple modeling of objects on the PHP heap, including constants, class objects, and merged objects.

- frontend
  
  Utilized by opensource project [php-parser](https://github.com/z7zmey/php-parser)

- ir

  Expressions and statements, with language-specific metadata.

# Taint Analysis
This solution is highly inspired by [Tai-e framework](https://github.com/pascal-lab/Tai-e), which is a new framework based on the latest reserchwork (until now 2023), and also Tai-e give a improvments conbined with P/Taint algorithm. P/Taint is a novel analysis technique that integrates taint propagation with pointer analysis (or alias analysis) as a whole. For more details, see [P/Taint](https://dl.acm.org/doi/pdf/10.1145/3133926).

## Context-Sensitive Types

Sensitive can be understood as the modeling of the scope of statements or variables within a program's execution context, which can be path sensitive or function/method sensitive. Consider the following scenario:

```php
function fun1($arg): string {
  $a = $obj->sayHello($arg);
  return $a;
}
$c = fun1($arg);
...
$d = fun1($arg);
```

In this case, `fun1` is executed twice, and the statement `$a = $obj->sayHello($arg);` along with the associated variable will have two different contexts. The purpose is to model the variable state as closely as possible to the runtime state through static context modeling.

Currently, only context sensitivity is implemented, without involving path sensitivity (which does not significantly improve the accuracy of analysis for object-oriented languages). Specifically, it includes the following types:

- Function/method sensitive
- Object sensitive

The context modeling is based on the assumption that any statement is always executed within some function/method. If it's a static function, the context is only related to the call site. If it's a method, in addition to the call site, it's also related to the object instance.

## Propagation Categories
- method/function internal same block scope propagation
- method/function call parameter/return value propagation
- class `$this` propagation
- class object field propagation
- class hierarchical method lookup

  not yet implemented, basic data structures are available, requiring `ast_visitor` to parse

## Assignment Classification
- var copy 

  `$a = $b;`
- literal assign

   `$a = "hello";`
- invoke assign 

  `$a = fun1($arg);` or `$a = $obj->sayHello($arg);`
- store array

  `$a[1] = $b;`
- load array

  `$b = $a[1];`
- store field 

  `$obj->name = $a;`
- load field 

  `$a = $obj->name;`

## Detection Process

`source code ---> ast node ---> ir ---> stmt visitor ---> solve by solver ---> taint collect`

- ir
  We only construct IR statements related to assignments, simplifying various assignment scenarios into a few simple categories in three-address form for easy analysis. For example:
  ```php
  $obj1->name = $obj2->name;
  ```
  will be transformed into:
  ```
  $temp1 = $obj2->name; // load field
  $obj1->name = $temp2; // store field
  ```

- stmt visitor
  Mainly used to construct initial assignment-related data structures, including pointer flow graph and function call graph `call graph`.

- solve by solver
  P/Taint algorithm iteration, resolving the possible value set for each var.

- taint collect
  Traverse all invoke statements, analyze var's value set, and determine if it is suspicious.

## Core Solve Algorithm
```
loop entry = worklist.poll() != null:
  diff = propagate(entry);
  if entry is pointer:
    processInstanceStore(entry, diff)
    processInstanceLoad(entry, diff)
    processArrayStore(entry, diff)
    processArrayLoad(entry, diff)
    processCall(entry, diff)
    processMerge(entry, diff)
  else if entry is calledge:
    processCallEdge(entry)
  end if
end loop
```
Model variable propagation as:
- The value of a variable `var` propagates on the pointer graph and call graph.
- If a `var1` has a new `diff` value, affected `var2` must be found on the pointer graph and the value added to `var2`'s value set.
- If this `var` has a corresponding invoke call, the context must be extended to this value.

# Strategy
Our detection strategy mainly involves two parts: enriching the mock with additional exploit points, including missed sinks and transfer functions, and comprehensive analysis determination.
## Taint Analyze
- Regular source (taint) ---> sink

  Regular taint propagation, effective for unaltered or some obvious backdoors, with high credibility.
- Hook arguments of certain special functions

  For example, some regex `e` mode, with high credibility.

- Obfuscated transformation

  Track the computed properties of `$var_fun` in `$var_fun($arg1, $arg2)`, such as after replace, concat, base decode, etc., with medium credibility.

  Detecting obfuscated transformations without introducing dynamic simulation execution is difficult for precise judgment.

## Flow Definition
Flow definition is implemented by defining built-in functions or classes in `mock.php`.
- Transfer functions like `base64_decode`, `explode`

  The mock functions transparently transfer out `var`. Note that the return statement concatenates "decode" and `$string`, adding a "decode" attribute to the return value and passing the latter through.

  ```php
  function base64_decode(string $string, bool $strict = false): string {
      return "decode".$string;
  }
  ```

  ```
  $a = base64_decode($_GET['cmd']);
  ```
  Therefore, `$a` will have the taint passed through and the "decode" attribute.

- Define source and sink

  If a new source/sink exploit point is discovered in the future, it can be defined in the mock PHP file. Note that the source can be an array/variable or a built-in function. If it's the former, directly mock a constant `taint` assignment.
  If it's a function, mock the return statement with `return "taint";`.

  ```php
  $_GET = [];
  $_GET[0] = "taint";
  ```

  ```php
  function file_get_contents(string $filename, bool $use_include_path, resource $context, int $offset, int $length): string {
      return "taint";
  }
  ```

  If it's a sink, define the corresponding sensitive parameter of the function as a variable with the `$sink` prefix. If there are multiple, define them as `$sink1`, `$sink2`, etc.

  ```php
  function system(string $sink, int &$result_code = null): string {
      return "nop";
  }
  ```

- Define built-in class

  For example, on the Windows platform, using PHP COM class binding to a specific COM object in Windows to execute commands.

  ```php
  class COM {
      public function exec(string $sink): string {
      }
      public function ShellExecute(string $sink1, string $sink2): int {
          return 0;
      }
  }
  ```

## What Happens with Unmocked Functions
It will cause the propagation of `var`'s value to be interrupted, will raise the rate of false negative.

## Pitfalls to Work around
- Avoid infinite loops

  Although static analysis can avoid resource exhaustion similar to logic bombs in actual execution, the analysis itself may enter an infinite loop.
- Function recursion

   Fixed by directly returning without expansion.
- Variable assignment

   Fixed, mainly occurring in binary assignment.
    ```php
    $a = $_GET[0];
    $a = $a."c";
    ```
- Limiting the number of iterations in the solve

    If a large PHP file defines many `var`s, it may lead to many iterations.

## TODO
- Continue to supplement detection logic

  There is still a large space for supplementing source/sink, requiring continued effort.
- Standardize the definition of source/sink

  The `taint` and `sink` definitions used in the definition have a very small probability of colliding with user-defined functions, which need to be fixed.
- Adapt to syntax cases

  Errors in batch test reports indicate uncovered syntax, requiring continued integration of samples to supplement semantic explanations to reduce these errors. This work is mainly in `ast_visitor`.
- Emmbed simulated vm
  
  trackable simplified vm, which mock the underlying level functionality like like network communication and file operation, etc.
