/**
 * @brief This file contains the patch for sceFontOpen to load custom fonts.
 */
#include "scefttt.h"

/* Patch Open Function */
int sceFtttOpen(int fontLibHandle, int index, int mode, int errorCodePtr)
{
    return sceFontOpenUserFile(fontLibHandle, (int)"disc0:/PSP_GAME/USRDIR/fonts.pgf", 0, errorCodePtr);
}