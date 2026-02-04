#pragma once

// The Patched Fuction. Handle the control flow to sceFontOpenUserFile
int sceFtttOpen(int fontLibHandle, int index, int mode, int errorCodePtr);
int sceFtttNewLib(int paramsPtr, int errorCodePtr);
int sceFtttGetFontInfo(int fontHandle, int fontInfoPtr);


// The Original Fuction Declaration. Stub Defined in sceLibFont.S
int sceFontOpenUserFile(int fontLibHandle, int fileNameAddr, int mode, int errorCodePtr);
int sceFontNewLib(int paramsPtr, int errorCodePtr);
int sceFontGetFontInfo(int fontHandle, int fontInfoPtr);