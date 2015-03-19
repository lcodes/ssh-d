Minimal D Bindings for the SSH library
======================================

This library provides incomplete bindings to the [libssh]() library.
The following headers have been converted:

* libssh/libssh.d
* libssh/server.d
* libssh/callbacks.d

It should be enough to implement the [sshd]() server example.

[libssh]: http://www.libssh.org
[sshd]:   https://github.com/substack/libssh/blob/master/examples/samplesshd-tty.c


License
-------

Copyright (c) 2003-2009 Aris Adamantiadis <aris@0xbadc0de.be>

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
