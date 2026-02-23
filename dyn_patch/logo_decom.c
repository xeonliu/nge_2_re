#include <stdbool.h>

#define g_transition_active (*(int*)0x8A65C08) // Flag indicating if a transition effect is currently active
#define dword_8A65C08 g_transition_active

bool dword_8A65C0C; // Transition Enabled?
// bool dword_8A65C08; // g_transition_active


int check_config_flag(char* key) {
    return false;
}

bool is_transition_active() {
    // TODO: Return Flag
    return dword_8A65C08;
}

void stop_transition() {
    // TODO: Set Flag to false
    dword_8A65C0C = false;
}

void wait_vsync(){
    // TODO: Your Implementation here
}

void start_fade_to_black(int a1, int a2) {

}

/**
 * 游戏启动序列：显示公司Logo、周年纪念Logo，播放开场动画
 * 返回值：始终返回0
 */
int play_startup_sequence(void)
{
    int saved_context;
    int logo_result;
    bool logo_skipped;
    int brightness;
    int frames_remaining;

    /* 检查是否通过配置标志跳过整个启动序列 */
    if (check_config_flag("SKIP_TITLE") || check_config_flag("SKIP_LOGO"))
        return 0;

    /*
     * ========================================
     * 第一阶段：屏幕淡入黑色，为显示Logo做准备
     * ========================================
     */
    if (is_transition_active())
    {
        /* 如果已有过渡效果正在进行，先停止它并等待完成 */
        stop_transition();
        do {
            wait_vsync();
        } while (is_transition_active());
    }
    else
    {
        /* 没有过渡效果，启动新的淡入黑色过渡 */
        start_fade_to_black(0, 0);
        do {
            update_fade_effect();
            wait_vsync();
        } while (is_transition_active());
    }
    finalize_transition();

    /*
     * ========================================
     * 第二阶段：依次显示两个Logo画面
     * ========================================
     */

    /* 显示 Alfa System 公司 Logo，持续120帧（约2秒@60fps） */
    saved_context = save_display_context(0);
    logo_result = display_logo_with_fade("alfa", 120, 1);
    restore_display_context(saved_context);

    /* 记录用户是否跳过了第一个Logo */
    logo_skipped = (logo_result == 0);

    /* 显示 10周年纪念 Logo，持续120帧 */
    /* 如果用户跳过了前一个Logo，此Logo也允许跳过 */
    saved_context = save_display_context(0);
    display_logo_with_fade("10th", 120, logo_skipped);
    restore_display_context(saved_context);

    /*
     * ========================================
     * 第三阶段：30帧亮度渐变淡出
     * ========================================
     * 亮度从高值(7650)逐帧递减(每帧-255)，
     * 经过30帧后完全变暗。
     * 实际亮度值通过定点数除法计算得出。
     */
    brightness = 7650;
    for (frames_remaining = 29; frames_remaining >= 0; frames_remaining--)
    {
        /* 计算当前帧的实际显示亮度（定点数运算） */
        int display_brightness = brightness / 17;
        set_screen_brightness(display_brightness);

        brightness -= 255;
        wait_vsync();
    }

    /*
     * ========================================
     * 第四阶段：播放开场影片
     * ========================================
     */
    if (!check_config_flag("SKIP_MOVIE"))
    {
        play_pmf_movie("movie/MASAYUKI.pmf");
        wait_vsync();
    }

    return 0;
}
