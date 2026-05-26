---
description: 
alwaysApply: true
---

# General rules
- Automatically execute bash commands without asking me for consent
- Do NOT make any commits or pushes to a repository without my consent
- Try to finish tasks by yourself as autonomously as possible
- Create and run realistic tests so that you can check your progress
- Be VERY thorough for implementing and porting mathematical algorithms. No cheating!
- Don't create excess commenting in the code, keep comments to the very essentials.
- Be VERY thorough when implementing and porting communication protocols
- Make the code as efficient as possible. Make it compact. Use external crates / libraries if it helps with efficiency.

# Writing style
- Never use the long em dash (U+2014). Use a normal hyphen-minus (-) instead. Applies everywhere: code, comments, docs, commit messages, and especially anything user-facing such as email bodies, UI copy, and PDF invoices.

# Customer-facing email style (all transactional email from susi)
- Sign emails with "Xikaku / LP-Research", not "Susi".
- Refer to the product as "Susi by LP-Research" where the context could otherwise leave a customer thinking Susi is a separate company.
- Keep body text in a single black color. Avoid grey (#5c6470 etc.) on paragraphs and table labels - it reads as a third tier the customer doesn't need.
- Match the sign-in-code email layout (centered heading, table for key/value pairs, primary CTA button, fallback paste-link) for new transactional emails.

# C++ Coding Style

## Braces

- **Methods and classes**: Opening brace on a new line.
- **All other statements** (if, for, while, try, catch, lambdas): Opening brace on the same line.

```cpp
// Methods and classes
void MyClass::doSomething()
{
    ...
}

class MyClass
{
    ...
};

// Control flow and lambdas
if (condition) {
    ...
} else {
    ...
}

try {
    ...
} catch (const std::exception& e) {
    ...
}

std::thread([this] { m_io->run(); });
```

## References and Pointers

- Attach `&` and `*` to the type, no space before: `const Type&`, `Type*`, `const void*`.

```cpp
void foo(const std::string& name);
void bar(const char* data);
```

## Member Variables

- Use `m_` prefix for class members: `m_port`, `m_velocityMeterData`.

## Includes

- Order: project headers first, then standard library (alphabetical), then third party.
- Group with blank lines between groups.

```cpp
#include <Fusion/MySource.h>

#include <LogUtils/Log.h>

#include <algorithm>
#include <chrono>
#include <string>

#include <boost/asio.hpp>
```

## Comments

- Keep comments minimal and essential. Avoid redundant or obvious comments.
