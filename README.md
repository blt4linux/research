# PAYDAY 2 - shared IDA structs

This repository contains (inside the `defs` directory) reverse-engineered type definitions
exported from IDA Pro. It also contains scripts to import and export the definitions from IDA Pro.

## Importing types

Run `import.py` in this directory. **You should only run this on new databases!** If it fails mid
import, your type definitions may be toast.

Note you may have to do this with your IDB located inside the repository folder - I'm not quite sure
how relative paths work with IDAPython.

## Exporting types

If you've made modifications you wish to contribute, run `export.py`. This will copy all non-excluded
local types into appropriate files in the `defs` directory. You should then review, commit and push your
changes with `git`.

## Notes

- Currently this only supports IDA 6.8 - I use this version due to plugin support, but if someone
using IDA 7.x wants to make an updated version, that would be great.
- ~~Currently this imports definitions in a basically random order, so if a definition depends on another
definition that has yet to be imported it won't import properly, causing a cascading effect. This shouldn't
be too hard to solve - before doing the main import, go through each type name and if it's not present in
the database, define it as a `void*` typedef or something, which is then replaced during the rest of the
import.~~ Implemented.

