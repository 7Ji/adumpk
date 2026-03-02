# adumpk

`adumpk.py` parses Alpine APK v3 ADB package files (used in OpenWrt 25.10 and above) and can optionally:

- convert package contents to a tar archive
- write parsed package metadata to JSON

## Usage

```bash
./adumpk.py <input.apk> (--tar <output.tar>) (--meta <output.json>)
```

### Examples:

To only print info

```bash
./adumpk.py /tmp/vim-full-9.2.0-r1.apk
```

To both print info, convert to tar, and create info JSON:

```bash
./adumpk.py /tmp/vim-full-9.2.0-r1.apk --tar /tmp/demo.tar --meta /tmp/demo.json
```

The output on terminal would be like the following:

```log
> ./adumpk.py /tmp/vim-full-9.2.0-r1.apk --tar /tmp/demo.tar --meta /tmp/demo.json
INFO.... Dumping APK '/tmp/vim-full-9.2.0-r1.apk'
INFO.... Schema: package
INFO....   [0] ADB payload=1840 compat=0 ver=0
INFO....     package metadata:
INFO....       name: vim-full
INFO....       version: 9.2.0-r1
INFO....       hashes: 041c1d3abe7483f8ed0c0b99973a642a3bfa003b
INFO....       description: Vim is an almost compatible version of the UNIX editor Vi. Normal build with standard set of features like syntax highlighting, menus, mouse support, translations, spell checking, etc.
INFO....       arch: aarch64_cortex-a53
INFO....       license: Vim
INFO....       origin: feeds/packages/feeds/packages/utils/vim
INFO....       url: https://www.vim.org/
INFO....       installed-size: 2747998
INFO....       depends: ['libc', 'vim-runtime=9.2.0-r1']
INFO....       provides: ['vim=9.2.0-r1', 'vim-full-any']
INFO....     all file paths (5):
INFO....       lib/apk/packages/vim-full.conffiles
INFO....       lib/apk/packages/vim-full.list
INFO....       lib/upgrade/keep.d/vim-full
INFO....       usr/bin/vim
INFO....       usr/bin/vimdiff
INFO....   [1] DATA path_idx=4 file_idx=1 data_len=13
INFO....       path=lib/apk/packages/vim-full.conffiles
INFO....   [2] DATA path_idx=4 file_idx=2 data_len=59
INFO....       path=lib/apk/packages/vim-full.list
INFO....   [3] DATA path_idx=6 file_idx=1 data_len=13
INFO....       path=lib/upgrade/keep.d/vim-full
INFO....   [4] DATA path_idx=8 file_idx=1 data_len=2747913
INFO....       path=usr/bin/vim
```

The converted tar is in a similar format for APK v2 (modified tar), albeit without .PKGINFO and .SIGN files as they won't make sense:

```log
> tar -tvf /tmp/demo.tar
drwxr-xr-x root/root         0 1970-01-01 08:00 lib/
drwxr-xr-x root/root         0 1970-01-01 08:00 lib/apk/
drwxr-xr-x root/root         0 1970-01-01 08:00 lib/apk/packages/
drwxr-xr-x root/root         0 1970-01-01 08:00 lib/upgrade/
drwxr-xr-x root/root         0 1970-01-01 08:00 lib/upgrade/keep.d/
drwxr-xr-x root/root         0 1970-01-01 08:00 usr/
drwxr-xr-x root/root         0 1970-01-01 08:00 usr/bin/
drwxr-xr-x root/root         0 1970-01-01 08:00 usr/share/
drwxr-xr-x root/root         0 1970-01-01 08:00 usr/share/vim/
lrwxrwxrwx root/root         0 2026-02-27 09:01 usr/bin/vimdiff -> vim
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA256'
-rw-r--r-- root/root        13 2026-02-27 09:01 lib/apk/packages/vim-full.conffiles
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA256'
-rw-r--r-- root/root        59 2026-02-27 09:01 lib/apk/packages/vim-full.list
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA256'
-rw-r--r-- root/root        13 2026-02-27 09:01 lib/upgrade/keep.d/vim-full
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA256'
-rwxr-xr-x root/root   2747913 2026-02-27 09:01 usr/bin/vim
```

The above warning can be ignored as they're APK v2 extension; it's recommended to use libarchive/bsdtar if you want these xattr, although as they're non-standard they would not be written to filesystem anyway:

```log
> sudo bsdtar --acls --xattrs -xvpf /tmp/demo.tar
x lib/
x lib/apk/
x lib/apk/packages/
x lib/upgrade/
x lib/upgrade/keep.d/
x usr/
x usr/bin/
x usr/share/
x usr/share/vim/
x usr/bin/vimdiff
x lib/apk/packages/vim-full.conffiles
x lib/apk/packages/vim-full.list
x lib/upgrade/keep.d/vim-full
x usr/bin/vim
```

The metadata json is as verbose as possible:

```json
{
  "apk": "/tmp/vim-full-9.2.0-r1.apk",
  "schemas": [
    {
      "dirs": [
        {
          "group": "root",
          "mode": 493,
          "path": "",
          "path_idx": 1,
          "user": "root",
          "xattrs": []
        },
        ...
        {
          "group": "root",
          "mode": 493,
          "path": "usr/share/vim",
          "path_idx": 10,
          "user": "root",
          "xattrs": []
        }
      ],
      "files": [
        {
          "device": null,
          "file_idx": 1,
          "group": "root",
          "hash_alg": "SHA256",
          "hash_hex": "a5d438fe2fcb67bf1411737115cedc25a3a805ae45d4d45a5f327b24d0089eaf",
          "kind": "file",
          "link_target": null,
          "mode": 420,
          "mtime": 1772154067,
          "name": "vim-full.conffiles",
          "path": "lib/apk/packages/vim-full.conffiles",
          "path_idx": 4,
          "size": 13,
          "user": "root",
          "xattrs": []
        },
        ...
        {
          "device": null,
          "file_idx": 2,
          "group": "root",
          "hash_alg": null,
          "hash_hex": null,
          "kind": "symlink",
          "link_target": "vim",
          "mode": 511,
          "mtime": 1772154067,
          "name": "vimdiff",
          "path": "usr/bin/vimdiff",
          "path_idx": 8,
          "size": 3,
          "user": "root",
          "xattrs": []
        }
      ],
      "metadata": {
        "arch": "aarch64_cortex-a53",
        "depends": [
          "libc",
          "vim-runtime=9.2.0-r1"
        ],
        "description": "Vim is an almost compatible version of the UNIX editor Vi. Normal build with standard set of features like syntax highlighting, menus, mouse support, translations, spell checking, etc.",
        "hashes": "041c1d3abe7483f8ed0c0b99973a642a3bfa003b",
        "installed-size": 2747998,
        "license": "Vim",
        "name": "vim-full",
        "origin": "feeds/packages/feeds/packages/utils/vim",
        "provides": [
          "vim=9.2.0-r1",
          "vim-full-any"
        ],
        "url": "https://www.vim.org/",
        "version": "9.2.0-r1"
      },
      "schema": "package"
    }
  ]
}
```


## License

**adumpk** is licensed under [**GPL3**](https://gnu.org/licenses/gpl.html)
 * Copyright (C) 2026 Guoxdin "7Ji" Pu (pugokushin@gmail.com)
 * This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version * of the License, or (at your option) any later version.
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
