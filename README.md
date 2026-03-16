# adumpk

`adumpk.py` parses Alpine APK v3 ADB package files (used in OpenWrt 25.12 and above) and can optionally:

- convert package contents to a tar archive
- write parsed package metadata to JSON

The definition of the ADB format is loosely defined by some schemas, and in most cases largely depends on the only implementation `apk-tools`' C source code. I've written a single blog post [Into Alpine APK v3 format: the binary perspective](https://7ji.github.io/designdoc/2026/03/03/into-Alpine-APK-v3-format-the-binary-perspective.html) about how to dig through such format which should be easier to follow.

## Usage

```bash
./adumpk.py (--help/-h) (--debug) (--tar <output.tar>) (--json <output.json>) <input.apk>
```

### Examples:

To only print info

```bash
./adumpk.py /tmp/vim-full-9.2.0-r1.apk
```

To both print info, convert to tar, and create info JSON:

```bash
./adumpk.py /tmp/vim-full-9.2.0-r1.apk --tar /tmp/demo.tar --json /tmp/demo.json
```

The output on terminal would be like the following:

```log
> ./adumpk.py /tmp/vim-full-9.2.0-r1.apk --tar /tmp/demo.tar --json /tmp/demo.json
INFO.... Dumping APK '/tmp/vim-full-9.2.0-r1.apk', and convert to tar '/tmp/demo.tar', and dump into to json '/tmp/demo.json'
INFO.... name             : vim-full
INFO.... version          : 9.2.0-r1
INFO.... sha1sum          : 7ddee5e3de5335f16040592b074a830e781f5346
INFO.... description      : Vim is an almost compatible version of the UNIX editor Vi. Normal build with standard set of features like syntax highlighting, menus, mouse support, translations, spell checking, etc.
INFO.... arch             : aarch64_cortex-a53
INFO.... license          : Vim
INFO.... origin           : feeds/packages/feeds/packages/utils/vim
INFO.... maintainer       : 
INFO.... url              : https://www.vim.org/
INFO.... repo_commit      : 
INFO.... build_time       : 
INFO.... installed_size   : 2747998
INFO.... file_size        : 
INFO.... provider_priority: 
INFO.... depends          : ['libc', 'vim-runtime=9.2.0-r1']
INFO.... provides         : ['vim=9.2.0-r1', 'vim-full-any']
INFO.... replaces         : []
INFO.... install_if       : []
INFO.... recommends       : []
INFO.... layer            : 
INFO.... tags             : []
INFO.... Paths:
INFO....   1,    drwxr-xr-x 0 root root                                        /
INFO....   2,    drwxr-xr-x 0 root root                                        lib/
INFO....   3,    drwxr-xr-x 0 root root                                        lib/apk/
INFO....   4,    drwxr-xr-x 0 root root                                        lib/apk/packages/
INFO....   4,  1 -rw-r--r-- 0 root root            13 Fri Mar  6 04:05:01 2026 lib/apk/packages/vim-full.conffiles
INFO....   4,  2 -rw-r--r-- 0 root root            59 Fri Mar  6 04:05:01 2026 lib/apk/packages/vim-full.list
INFO....   5,    drwxr-xr-x 0 root root                                        lib/upgrade/
INFO....   6,    drwxr-xr-x 0 root root                                        lib/upgrade/keep.d/
INFO....   6,  1 -rw-r--r-- 0 root root            13 Fri Mar  6 04:05:01 2026 lib/upgrade/keep.d/vim-full
INFO....   7,    drwxr-xr-x 0 root root                                        usr/
INFO....   8,    drwxr-xr-x 0 root root                                        usr/bin/
INFO....   8,  1 -rwxr-xr-x 0 root root       2747913 Fri Mar  6 04:05:01 2026 usr/bin/vim
INFO....   8,  2 lrwxrwxrwx 0 root root               Fri Mar  6 04:05:01 2026 usr/bin/vimdiff -> vim
INFO....   9,    drwxr-xr-x 0 root root                                        usr/share/
INFO....  10,    drwxr-xr-x 0 root root                                        usr/share/vim/
INFO.... Scripts:
INFO.... postinst (b'#!/bin/sh\n[ "${IPKG_NO_SC' ... b'nd_user\ndefault_postinst\n') len=230
INFO.... predeinst (b'#!/bin/sh\n[ -s ${IPKG_INS' ... b'"vim-full"\ndefault_prerm\n') len=168
INFO.... postupgrade (b'#!/bin/sh\nexport PKG_UPGR' ... b'nd_user\ndefault_postinst\n') len=251
```

The converted tar is in a similar format for APK v2 (modified tar), albeit without .PKGINFO and .SIGN files as they won't make sense:

```log
> tar -tvf /tmp/demo.tar
drwxr-xr-x root/root         0 1970-01-01 08:00 lib/
drwxr-xr-x root/root         0 1970-01-01 08:00 lib/apk/
drwxr-xr-x root/root         0 1970-01-01 08:00 lib/apk/packages/
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.sha256'
-rw-r--r-- root/root        13 2026-03-06 04:05 lib/apk/packages/vim-full.conffiles
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.sha256'
-rw-r--r-- root/root        59 2026-03-06 04:05 lib/apk/packages/vim-full.list
drwxr-xr-x root/root         0 1970-01-01 08:00 lib/upgrade/
drwxr-xr-x root/root         0 1970-01-01 08:00 lib/upgrade/keep.d/
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.sha256'
-rw-r--r-- root/root        13 2026-03-06 04:05 lib/upgrade/keep.d/vim-full
drwxr-xr-x root/root         0 1970-01-01 08:00 usr/
drwxr-xr-x root/root         0 1970-01-01 08:00 usr/bin/
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.sha256'
-rwxr-xr-x root/root   2747913 2026-03-06 04:05 usr/bin/vim
lrwxrwxrwx root/root         3 2026-03-06 04:05 usr/bin/vimdiff -> vim
drwxr-xr-x root/root         0 1970-01-01 08:00 usr/share/vim/

```

The above warning can be ignored as they're APK v2 extension; it's recommended to use libarchive/bsdtar if you want these xattr, although as they're non-standard they would not be written to filesystem anyway:

```log
> sudo bsdtar --acls --xattrs -xvpf /tmp/demo.tar
x lib/
x lib/apk/
x lib/apk/packages/
x lib/apk/packages/vim-full.conffiles
x lib/apk/packages/vim-full.list
x lib/upgrade/
x lib/upgrade/keep.d/
x lib/upgrade/keep.d/vim-full
x usr/
x usr/bin/
x usr/bin/vim
x usr/bin/vimdiff
x usr/share/
x usr/share/vim/
```

The metadata json is as verbose as possible:

```json
{"pkginfo": {"name": "vim-full", "version": "9.2.0-r1", "checksum": {"type": "sha1", "value": "7ddee5e3de5335f16040592b074a830e781f5346"}, "description": "Vim is an almost compatible version of the UNIX editor Vi. Normal build with standard set of features like syntax highlighting, menus, mouse support, translations, spell checking, etc.", "arch": "aarch64_cortex-a53", "license": "Vim", "origin": "feeds/packages/feeds/packages/utils/vim", "maintainer": "", "url": "https://www.vim.org/", "repo_commit": "", "build_time": "", "installed_size": "2747998", "file_size": "", "provider_priority": "", "depends": ["libc", "vim-runtime<=9.2.0-r1"], "provides": ["vim<=9.2.0-r1", "vim-full-any"], "replaces": [], "install_if": [], "recommends": [], "layer": "", "tags": []}, "paths": [{"name": "", "acl": {"mode": "0o755", "user": "root", "group": "root", "xattrs": []}, "files": []}, {"name": "lib", "acl": {"mode": "0o755", "user": "root", "group": "root", "xattrs": []}, "files": []}, {"name": "lib/apk", "acl": {"mode": "0o755", "user": "root", "group": "root", "xattrs": []}, "files": []}, {"name": "lib/apk/packages", "acl": {"mode": "0o755", "user": "root", "group": "root", "xattrs": []}, "files": [{"name": "vim-full.conffiles", "acl": {"mode": "0o644", "user": "root", "group": "root", "xattrs": []}, "size": "13", "mtime": "1772741101", "hashes": {"type": "sha256", "value": "a5d438fe2fcb67bf1411737115cedc25a3a805ae45d4d45a5f327b24d0089eaf"}, "target": "", "kind": "regular", "dev": {}}, {"name": "vim-full.list", "acl": {"mode": "0o644", "user": "root", "group": "root", "xattrs": []}, "size": "59", "mtime": "1772741101", "hashes": {"type": "sha256", "value": "a4c39b1cd7403e93c30be319c4839832a04dc08278ff01aa48ade5131912c3c2"}, "target": "", "kind": "regular", "dev": {}}]}, {"name": "lib/upgrade", "acl": {"mode": "0o755", "user": "root", "group": "root", "xattrs": []}, "files": []}, {"name": "lib/upgrade/keep.d", "acl": {"mode": "0o755", "user": "root", "group": "root", "xattrs": []}, "files": [{"name": "vim-full", "acl": {"mode": "0o644", "user": "root", "group": "root", "xattrs": []}, "size": "13", "mtime": "1772741101", "hashes": {"type": "sha256", "value": "a5d438fe2fcb67bf1411737115cedc25a3a805ae45d4d45a5f327b24d0089eaf"}, "target": "", "kind": "regular", "dev": {}}]}, {"name": "usr", "acl": {"mode": "0o755", "user": "root", "group": "root", "xattrs": []}, "files": []}, {"name": "usr/bin", "acl": {"mode": "0o755", "user": "root", "group": "root", "xattrs": []}, "files": [{"name": "vim", "acl": {"mode": "0o755", "user": "root", "group": "root", "xattrs": []}, "size": "2747913", "mtime": "1772741101", "hashes": {"type": "sha256", "value": "65d03e9b1cf6782a19a042c4711035158470fbda7a89ef6fa018ac4a20fc1f27"}, "target": "", "kind": "regular", "dev": {}}, {"name": "vimdiff", "acl": {"mode": "0o777", "user": "root", "group": "root", "xattrs": []}, "size": "3", "mtime": "1772741101", "hashes": {"type": "none", "value": ""}, "target": "vim", "kind": "symlink", "dev": {}}]}, {"name": "usr/share", "acl": {"mode": "0o755", "user": "root", "group": "root", "xattrs": []}, "files": []}, {"name": "usr/share/vim", "acl": {"mode": "0o755", "user": "root", "group": "root", "xattrs": []}, "files": []}], "scripts": {"trigger": "", "preinst": "", "postinst": "IyEvYmluL3NoClsgIiR7SVBLR19OT19TQ1JJUFR9IiA9ICIxIiBdICYmIGV4aXQgMApbIC1zICR7SVBLR19JTlNUUk9PVH0vbGliL2Z1bmN0aW9ucy5zaCBdIHx8IGV4aXQgMAouICR7SVBLR19JTlNUUk9PVH0vbGliL2Z1bmN0aW9ucy5zaApleHBvcnQgcm9vdD0iJHtJUEtHX0lOU1RST09UfSIKZXhwb3J0IHBrZ25hbWU9InZpbS1mdWxsIgphZGRfZ3JvdXBfYW5kX3VzZXIKZGVmYXVsdF9wb3N0aW5zdAo=", "predeinst": "IyEvYmluL3NoClsgLXMgJHtJUEtHX0lOU1RST09UfS9saWIvZnVuY3Rpb25zLnNoIF0gfHwgZXhpdCAwCi4gJHtJUEtHX0lOU1RST09UfS9saWIvZnVuY3Rpb25zLnNoCmV4cG9ydCByb290PSIke0lQS0dfSU5TVFJPT1R9IgpleHBvcnQgcGtnbmFtZT0idmltLWZ1bGwiCmRlZmF1bHRfcHJlcm0K", "postdeinst": "", "preupgrade": "", "postupgrade": "IyEvYmluL3NoCmV4cG9ydCBQS0dfVVBHUkFERT0xClsgIiR7SVBLR19OT19TQ1JJUFR9IiA9ICIxIiBdICYmIGV4aXQgMApbIC1zICR7SVBLR19JTlNUUk9PVH0vbGliL2Z1bmN0aW9ucy5zaCBdIHx8IGV4aXQgMAouICR7SVBLR19JTlNUUk9PVH0vbGliL2Z1bmN0aW9ucy5zaApleHBvcnQgcm9vdD0iJHtJUEtHX0lOU1RST09UfSIKZXhwb3J0IHBrZ25hbWU9InZpbS1mdWxsIgphZGRfZ3JvdXBfYW5kX3VzZXIKZGVmYXVsdF9wb3N0aW5zdAo="}}
```


## License

**adumpk** is licensed under [**GPL3**](https://gnu.org/licenses/gpl.html)
 * Copyright (C) 2026 Guoxdin "7Ji" Pu (pugokushin@gmail.com)
 * This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version * of the License, or (at your option) any later version.
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
