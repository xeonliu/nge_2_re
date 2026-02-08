#ifndef __IMAGE_DISPLAY_H__
#define __IMAGE_DISPLAY_H__

/**
 * Load and display a raw RGBA8888 image from file.
 * 
 * @param filename Path to the raw image file
 * @param width Image width in pixels
 * @param height Image height in pixels
 * @param duration_ms Duration to display the image in milliseconds
 */
void displayImageFromFile(const char* filename, int width, int height, int duration_ms);

#endif
