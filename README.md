MachO
=====

MachO is a small Ruby library for parsing interesting data from [Mach-O][]
binaries.  It understands "normal" Mach-O binaries as well as multiarchitecure
[fat binarys].

It also includes an encryption simulation routine that is helpful in guessing
the final size of an encrypted binary.

[Mach-O]: http://en.wikipedia.org/wiki/Mach-O
[fat binarys]: http://en.wikipedia.org/wiki/Fat_binary

Parsing
-------

    require 'macho'
    exec = MachO::Executable.new("MyBinary")
    puts "Binary contains %d architectures" % exec.archs.length

Simulating Encryption
---------------------

The encryption simulation routine modifies the provided binary file by filling
its encryption segments with random bytes.  You should generally run this step
on a copy of your binary.

    require 'macho'
    MachO::simulate_encrypt("MyBinary")

Compressing the modified binary (using `gzip`) should give a representative
size estimate of how Apple's encryption pass will affect the binary's size.

Contributing
------------

Fork the [macho repository on GitHub](https://github.com/booyah/macho) and
send a Pull Request.

Copying
-------

Copyright © 2011, Booyah, Inc. See the `COPYING` file for license
rights and limitations (MIT).
