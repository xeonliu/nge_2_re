There are two tables in ELF.
One for offsets.
One for UTF-16 LE encoded characters.

When Patch the ELF, just Patch the UTF-16 LE encoded characters.
The Text should be replaced according to the new Encoding Table. 