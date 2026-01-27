#pragma once

// The Patched Fuction. Handle the control flow to sceFontOpenUserFile
int sceFtttOpen(int fontLibHandle, int index, int mode, int errorCodePtr);

// The Original Fuction Declaration. Stub Defined in sceLibFont.S
int sceFontOpenUserFile(int fontLibHandle, int fileNameAddr, int mode, int errorCodePtr);