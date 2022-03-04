# shellcode_injector

POC x64 injector for windows.
Injector scatters dll's executable section over free rwx pages.
It places absolute jmps after jcc. Dll must be compiled with clang extension (mcmodel=large and -fno-jump-tables).

For educational purposes only.

## demo

![demo](old%20demo.PNG)

## credits:

https://github.com/btbd/modmap

https://github.com/capstone-engine/capstone

https://github.com/JustasMasiulis/lazy_importer

