## PHP WebShell Detection Project Introduction

A static program analysis technology to detect PHP WebShells. It examines whether a PHP script has external controllable input variables used to deliver dangerous commands. Given the complexity of actual scripts, which may include arrays, classes, and various structural statements, how can we model these in a static context?

Pointer analysis or alias analysis is an important branch of static program analysis, primarily addressing the question of which possible values a variable in a statement might point to without running the program. We supports k-callsite-n and ci (insensitive context).

```php
<?php
shell_exec("/tmp/bd " . $_POST['port'] . " " . $_POST['bind_pass'] . " &");
?>
```

Output:

```text
type:normal msg="[%temp2_6=shell_exec(%temp2_17)]$sink:0--->[[]const6_taint,[]merged0_]"
```

- context

  Context sensitivity is crucial, currently implemented as k-callsite-n, with n defaulting to 2.

- heap

  Simple modeling of objects on the PHP heap, including constants, class objects, and merged objects.

- ir

  Expressions form statements, with language-specific metadata.

- taint

  P/Taint is a novel analysis technique that integrates taint propagation with pointer analysis (or alias analysis) as a whole. For more details, see [P/Taint](https://dl.acm.org/doi/pdf/10.1145/3133926).

### Context-Sensitive Types

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

### Taint Analysis

P/Taint is a novel analysis technique that integrates taint propagation with pointer analysis (or alias analysis) as a whole. For more details, see [P/Taint](https://dl.acm.org/doi/pdf/10.1145/3133926).

#### Context-Sensitive Types

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

#### Taint Analysis

P/Taint is a novel analysis technique that integrates taint propagation with pointer analysis (or alias analysis) as a whole. For more details, see [P/Taint](https://dl.acm.org/doi/pdf/10.1145/3133926).

##### Taint Analysis

- Regular source (taint) -> sink
- Hooking specific function arguments
- Obfuscation transformation

#### Flow Definition

Flow definition is implemented through defining built-in functions or classes in `mock.php`. This includes:

- Transfer functions like `base64_decode`, `explode`
- Defining source and sink
- Defining built-in classes

#### Strategy

The detection strategy involves two main parts: enriching the mock with new exploit points, including missed sinks and transfer functions, and comprehensive analysis judgment.

#### Taint Analyze

- Regular source (taint) -> sink
- Hooking specific function arguments
- Obfuscation transformation

#### Flow Definition

Flow definition is implemented through defining built-in functions or classes in `mock.php`. This includes:

- Transfer functions like `base64_decode`, `explode`
- Defining source and sink
- Defining built-in classes

#### What Happens with Unmocked Functions

This could lead to a break in the value propagation, resulting in missed detections (false negatives).

#### Pitfalls to Avoid

- Infinite loops
- Recursion in functions
- Binary assignments