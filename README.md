# Argon2
## C# wrapper context class

This is a C# class that wraps the native C functions 
from the Argon2 shared lib/Argon2OptDll library.

The [official Argon2 C implementation](https://github.com/P-H-C/phc-winner-argon2) was used here.

For more information about compilation/which version was used, check out [lib/README.md](https://github.com/GlitchedPolygons/Argon2Sharp/tree/master/lib) too!

### Usage

You can just add this repo as a git submodule to your own C# project and reference `Argon2Sharp.csproj`.

This should automatically copy the necessary [`lib/`](https://github.com/GlitchedPolygons/Argon2Sharp/tree/master/lib) folder to your project's output build directory...

In case it doesn't (or in case you're manually adding/embedding the C# class to your project), don't forget to copy it yourself to your output bin dir!