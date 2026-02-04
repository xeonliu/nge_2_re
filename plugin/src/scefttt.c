/**
 * @brief This file contains the patch for sceFontOpen to load custom fonts.
 */
#include <pspkernel.h>

#include "scefttt.h"

// https://github.com/uofw/uofw/blob/master/include/common/errors.h#L286
#define SCE_ERROR_KERNEL_LIBRARY_IS_NOT_LINKED 0x8002013A

// https://www.psdevwiki.com/vita/Error_Codes
#define SCE_FONT_ERROR_FILEOPEN 0x80460005
#define SCE_FONT_ERROR_FILECLOSE 0x80460006
#define SCE_FONT_ERROR_FILEREAD 0x80460007
#define SCE_FONT_ERROR_FILESEEK 0x80460008

// https://github.com/hz86/mgspw/blob/master/jmpfont.c
typedef struct sceFont_t_initRec
{
    void *userData;
    unsigned long maxNumFonts;
    void *cache;
    void *(*allocFunc)(void *, unsigned long);
    void (*freeFunc)(void *, void *);
    void *(*openFunc)(void *, void *, signed long *);
    signed long (*closeFunc)(void *, void *);
    unsigned long (*readFunc)(void *, void *, void *, unsigned long, unsigned long, signed long *);
    signed long (*seekFunc)(void *, void *, unsigned long);
    signed long (*onErrorFunc)(void *, signed long);
    signed long (*whenDoneReadFunc)(void *, signed long);
} sceFont_t_initRec;

typedef u32 u32_le;
typedef u16 u16_le;
typedef u64 u64_le;

typedef s32 s32_le;
typedef s16 s16_le;
typedef s64 s64_le;

typedef float float_le;
typedef double double_le;

/** https://github.com/hrydgard/ppsspp/blob/master/Core/Font/PGF.h */
typedef struct PGFFontStyle
{
    float_le fontH;
    float_le fontV;
    float_le fontHRes;
    float_le fontVRes;
    float_le fontWeight;
    u16_le fontFamily;
    u16_le fontStyle;
    // Check.
    u16_le fontStyleSub;
    u16_le fontLanguage;
    u16_le fontRegion;
    u16_le fontCountry;
    char fontName[64];
    char fontFileName[64];
    u32_le fontAttributes;
    u32_le fontExpire;
} PGFFontStyle;

typedef struct PGFFontInfo
{
    // Glyph metrics (in 26.6 signed fixed-point).
    s32_le maxGlyphWidthI;
    s32_le maxGlyphHeightI;
    s32_le maxGlyphAscenderI;
    s32_le maxGlyphDescenderI;
    s32_le maxGlyphLeftXI;
    s32_le maxGlyphBaseYI;
    s32_le minGlyphCenterXI;
    s32_le maxGlyphTopYI;
    s32_le maxGlyphAdvanceXI;
    s32_le maxGlyphAdvanceYI;

    // Glyph metrics (replicated as float).
    float_le maxGlyphWidthF;
    float_le maxGlyphHeightF;
    float_le maxGlyphAscenderF;
    float_le maxGlyphDescenderF;
    float_le maxGlyphLeftXF;
    float_le maxGlyphBaseYF;
    float_le minGlyphCenterXF;
    float_le maxGlyphTopYF;
    float_le maxGlyphAdvanceXF;
    float_le maxGlyphAdvanceYF;

    // Bitmap dimensions.
    s16_le maxGlyphWidth;
    s16_le maxGlyphHeight;
    s32_le numGlyphs;
    s32_le shadowMapLength; // Number of elements in the font's shadow charmap.

    // Font style (used by font comparison functions).
    PGFFontStyle fontStyle;

    u8 BPP; // Font's BPP.
    u8 pad[3];
} PGFFontInfo;

/* Custom IO Functions */
static void *my_open(void *pdata, char *filename, int *error)
{
    SceUID fd = sceIoOpen(filename, PSP_O_RDONLY, 0);
    if (fd < 0)
    {
        *error = SCE_FONT_ERROR_FILEOPEN;
        return 0;
    }
    *error = 0;
    return (void *)fd;
}

static int my_close(void *pdata, void *fileid)
{
    return sceIoClose((SceUID)fileid) < 0 ? SCE_FONT_ERROR_FILECLOSE : 0;
}

static int my_read(void *pdata, void *fileid, void *pbuf, int byte, int unit, int *error)
{
    int count = byte * unit;
    int retv = sceIoRead((SceUID)fileid, pbuf, count);
    if (retv < count)
    {
        *error = SCE_FONT_ERROR_FILEREAD;
        return 0;
    }
    *error = 0;
    return unit;
}

static int my_seek(void *pdata, void *fileid, int offset)
{
    return sceIoLseek32((SceUID)fileid, offset, PSP_SEEK_SET) < 0 ? SCE_FONT_ERROR_FILESEEK : 0;
}

/* Patch IO Functions */
int sceFtttNewLib(int paramsPtr, int errorCodePtr){
    sceFont_t_initRec *params = (sceFont_t_initRec *)paramsPtr;
    
    if (params->openFunc == NULL)
    {
        params->openFunc = (void *)my_open;
        params->closeFunc = (void *)my_close;
        params->readFunc = (void *)my_read;
        params->seekFunc = (void *)my_seek;
    }

    int ret;

    while ((ret = sceFontNewLib((int)params, errorCodePtr)) == SCE_ERROR_KERNEL_LIBRARY_IS_NOT_LINKED)
    {
        sceKernelDelayThread(200000);
    }

    return ret;
}


/* Patch Open Function */
int sceFtttOpen(int fontLibHandle, int index, int mode, int errorCodePtr)
{
    return sceFontOpenUserFile(fontLibHandle, (int)"disc0:/PSP_GAME/USRDIR/fonts.pgf", 0, errorCodePtr);
}

/* Patch Font Info in Memory */
int sceFtttGetFontInfo(int fontHandle, int fontInfoPtr)
{
    PGFFontInfo *fontInfo = (PGFFontInfo *)fontInfoPtr;

    int ret = sceFontGetFontInfo(fontHandle, fontInfoPtr);

    /* Make sure it's the same with PSP's pre-installed jpn0.pgf, Otherwise the font will glitch in PPSSPP. */
    // Change Max Width to 0x0013 pixels
    fontInfo->maxGlyphWidth = 0x0013;
    // Change Max Height to 0x0014 pixels
    fontInfo->maxGlyphHeight = 0x0014;

    return ret;
}