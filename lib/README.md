These binaries were built from the Apache-2.0 licensed [official Argon2 C implementation (master branch, commit from 2020-07-09)](https://github.com/P-H-C/phc-winner-argon2/commit/440ceb9612d5a20997e3e12728542df2de713ca4) using Clang on Linux and Mac, and MSVC 2019 on Windows.

Currently, only x64 CPU architectures are included, but you're free to add more (e.g. `arm64-v8`) yourself!

Copy this entire `lib/` folder to your project's output build directory: the Argon2Sharp context class automatically loads the correct shared library for your platform and OS.
