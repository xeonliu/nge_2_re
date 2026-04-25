https://problemkaputt.de/psx-spx.htm#CDROMISOFileandDirectoryDescriptors


CDROM ISO File and Directory Descriptors

The location of the Root Directory is described by a 34-byte Directory Record being located in Primary Volume Descriptor entries 09Ch..0BDh. The data therein is: Block Number (usually 22 on PSX disks), LEN_FI=01h, Name=00h, and, LEN_SU=00h (due to the 34-byte limit).

Format of a Directory Record
  00h 1      Length of Directory Record (LEN_DR) (33+LEN_FI+pad+LEN_SU) (0=Pad)
  01h 1      Extended Attribute Record Length (usually 00h)
  02h 8      Data Logical Block Number (2x32bit)
  0Ah 8      Data Size in Bytes        (2x32bit)
  12h 7      Recording Timestamp       (yy-1900,mm,dd,hh,mm,ss,timezone)
  19h 1      File Flags 8 bits         (usually 00h=File, or 02h=Directory)
  1Ah 1      File Unit Size            (usually 00h)
  1Bh 1      Interleave Gap Size       (usually 00h)
  1Ch 4      Volume Sequence Number    (2x16bit, usually 0001h)
  20h 1      Length of Name            (LEN_FI)
  21h LEN_FI File/Directory Name ("FILENAME.EXT;1" or "DIR_NAME" or 00h or 01h)
  xxh 0..1   Padding Field (00h) (only if LEN_FI is even)
  xxh LEN_SU System Use (LEN_SU bytes) (see below for CD-XA disks)
LEN_SU can be calculated as "LEN_DR-(33+LEN_FI+Padding)". For CD-XA disks (as used in the PSX), LEN_SU is 14 bytes:
  00h 2      Owner ID Group  (whatever, usually 0000h, big endian)
  02h 2      Owner ID User   (whatever, usually 0000h, big endian)
  04h 2      File Attributes (big endian):
               0   Owner Read    (usually 1)
               1   Reserved      (0)
               2   Owner Execute (usually 1)
               3   Reserved      (0)
               4   Group Read    (usually 1)
               5   Reserved      (0)
               6   Group Execute (usually 1)
               7   Reserved      (0)
               8   World Read    (usually 1)
               9   Reserved      (0)
               10  World Execute (usually 1)
               11  IS_MODE2        (0=MODE1 or CD-DA, 1=MODE2)
               12  IS_MODE2_FORM2  (0=FORM1, 1=FORM2)
               13  IS_INTERLEAVED  (0=No, 1=Yes...?) (by file and/or channel?)
               14  IS_CDDA         (0=Data or ADPCM, 1=CD-DA Audio Track)
               15  IS_DIRECTORY    (0=File or CD-DA, 1=Directory Record)
             Commonly used Attributes are:
               0D55h=Normal Binary File (with 800h-byte sectors)
               1555h=Uncommon           (fade to black .DPS and .XA files)
               2555h=Uncommon           (wipeout .AV files) (MODE1 ??)
               4555h=CD-DA Audio Track  (wipeout .SWP files, alone .WAV file)
               3D55h=Streaming File     (ADPCM and/or MDEC or so)
               8D55h=Directory Record   (parent-, current-, or sub-directory)
  06h 2      Signature     ("XA")
  08h 1      File Number   (Must match Subheader's File Number)
  09h 5      Reserved      (00h-filled)
Directory sectors do usually have zeropadding at the end of each sector:
  - Directory sizes are always rounded up to N*800h-bytes.
  - Directory entries should not cross 800h-byte sector boundaries.
  There may be further directory entries on the next sector after the padding.
  To deal with that, skip 00h-bytes until finding a nonzero LEN_DR value (or
  slightly faster, upon a 00h-byte, directly jump to next sector instead of
  doing a slow byte-by-byte skip).
  Note: Padding between sectors does rarely happen on PSX discs because the
  PSX kernel supports max 800h bytes per directory (one exception is PSX Hot
  Shots Golf 2, which has an ISO directory with more than 800h bytes; it does
  use a lookup file instead of actually parsing the while ISO directory).
Names are alphabetically sorted, no matter if the names refer to files or directories (ie. SUBDIR would be inserted between STRFILE.EXT and SYSFILE.EXT). The first two entries (with non-ascii names 00h and 01h) are referring to current and parent directory.