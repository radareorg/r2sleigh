uint32_t sym__xxhash32(uint64_t RDI_0, uint64_t RSI_0, uint32_t EDX_0)
{
    uint32_t sym__rotl32(uint32_t, uint8_t);

    /* r2dec proof: no individual construct is marked; 416 source obligations: 312 rendered, 104 elided, 0 refused; 94 statements rendered */
    {
        uint64_t stack_m40;
        int32_t stack_m28;
        uint64_t stack_m24;
        uint64_t stack_m16;
        uint64_t tmp_11f80_1;
        uint64_t tmp_11f80_2;
        uint64_t tmp_11f80_6;
        uint32_t stack_m44;
        stack_m16 = RDI_0;
        stack_m24 = RSI_0;
        stack_m28 = (int32_t)EDX_0;
        tmp_11f80_1 = stack_m16;
        tmp_11f80_2 = stack_m24;
        tmp_11f80_2 = stack_m24;
        tmp_11f80_2 = stack_m24;
        stack_m40 = tmp_11f80_1 + tmp_11f80_2;
        tmp_11f80_2 = stack_m24;
        {
            int32_t tmp_11f00_1;
            if (tmp_11f80_2 < 16) {
                tmp_11f00_1 = (int32_t)stack_m28;
                stack_m44 = (uint32_t)tmp_11f00_1 + 0x165667b1;
            } else {
                int32_t stack_m60;
                int32_t stack_m64;
                int32_t stack_m72;
                tmp_11f80_6 = stack_m40;
                uint64_t stack_m56 = tmp_11f80_6 - 16;
                tmp_11f00_1 = (int32_t)stack_m28;
                stack_m60 = (int32_t)((uint32_t)tmp_11f00_1 + 0x24234428);
                tmp_11f00_1 = (int32_t)stack_m28;
                stack_m64 = (int32_t)((uint32_t)tmp_11f00_1 - 0x7a143589);
                tmp_11f00_1 = (int32_t)stack_m28;
                tmp_11f00_1 = (int32_t)stack_m28;
                stack_m72 = (int32_t)((uint32_t)tmp_11f00_1 + 0x61c8864f);
                for (; ; ) {
                    tmp_11f80_1 = stack_m16;
                    int32_t tmp_11f00_6 = (int32_t)*(uint32_t*)tmp_11f80_1;
                    uint32_t RAX_17 = sym__rotl32((uint32_t)((uint32_t)((uint64_t)tmp_11f00_6 * 0xffffffff85ebca77U) + (uint32_t)stack_m60), 13);
                    stack_m60 = (int32_t)((uint64_t)(int32_t)RAX_17 * 0xffffffff9e3779b1U);
                    tmp_11f80_1 = stack_m16;
                    stack_m16 = tmp_11f80_1 + 4;
                    tmp_11f80_1 = stack_m16;
                    int32_t tmp_11f00_9 = (int32_t)*(uint32_t*)tmp_11f80_1;
                    uint32_t RAX_24 = sym__rotl32((uint32_t)((uint32_t)((uint64_t)tmp_11f00_9 * 0xffffffff85ebca77U) + (uint32_t)stack_m64), 13);
                    stack_m64 = (int32_t)((uint64_t)(int32_t)RAX_24 * 0xffffffff9e3779b1U);
                    tmp_11f80_1 = stack_m16;
                    stack_m16 = tmp_11f80_1 + 4;
                    tmp_11f80_1 = stack_m16;
                    int32_t tmp_11f00_12 = (int32_t)*(uint32_t*)tmp_11f80_1;
                    uint32_t RAX_31 = sym__rotl32((uint32_t)((uint32_t)((uint64_t)tmp_11f00_12 * 0xffffffff85ebca77U) + (uint32_t)tmp_11f00_1), 13);
                    tmp_11f00_1 = (int32_t)((uint64_t)(int32_t)RAX_31 * 0xffffffff9e3779b1U);
                    tmp_11f80_1 = stack_m16;
                    stack_m16 = tmp_11f80_1 + 4;
                    tmp_11f80_1 = stack_m16;
                    int32_t tmp_11f00_15 = (int32_t)*(uint32_t*)tmp_11f80_1;
                    uint32_t RAX_38 = sym__rotl32((uint32_t)((uint32_t)((uint64_t)tmp_11f00_15 * 0xffffffff85ebca77U) + (uint32_t)stack_m72), 13);
                    stack_m72 = (int32_t)((uint64_t)(int32_t)RAX_38 * 0xffffffff9e3779b1U);
                    tmp_11f80_1 = stack_m16;
                    stack_m16 = tmp_11f80_1 + 4;
                    tmp_11f80_1 = stack_m16;
                    if (stack_m56 < tmp_11f80_1) {
                        break;
                    }
                }
                {
                    uint32_t RAX_43 = sym__rotl32((uint32_t)stack_m60, 1);
                    uint32_t RAX_44 = sym__rotl32((uint32_t)stack_m64, 7);
                    uint32_t RAX_47 = sym__rotl32((uint32_t)tmp_11f00_1, 12);
                    uint32_t RAX_50 = sym__rotl32((uint32_t)stack_m72, 18);
                    stack_m44 = RAX_43 + RAX_44 + RAX_47 + RAX_50;
                }
            }
        }
        {
            uint32_t stack_m44_2;
            tmp_11f80_2 = stack_m24;
            stack_m44_2 = (uint32_t)tmp_11f80_2 + stack_m44;
            for (; ; ) {
                tmp_11f80_1 = stack_m16;
                tmp_11f80_6 = stack_m40;
                if (tmp_11f80_6 < tmp_11f80_1 + 4) {
                    break;
                } else {
                    tmp_11f80_1 = stack_m16;
                    uint32_t tmp_11f00_31 = *(uint32_t*)tmp_11f80_1;
                    uint32_t RAX_64 = sym__rotl32((uint32_t)((uint32_t)((uint64_t)(int32_t)tmp_11f00_31 * 0xffffffffc2b2ae3dU) + stack_m44_2), 17);
                    stack_m44_2 = (uint32_t)((uint64_t)(int32_t)RAX_64 * 0x27d4eb2f);
                    tmp_11f80_1 = stack_m16;
                    stack_m16 = tmp_11f80_1 + 4;
                }
            }
            {
                for (; ; ) {
                    tmp_11f80_1 = stack_m16;
                    tmp_11f80_6 = stack_m40;
                    if (tmp_11f80_6 <= tmp_11f80_1) {
                        break;
                    } else {
                        tmp_11f80_1 = stack_m16;
                        uint8_t tmp_11e00_2 = *(uint8_t*)tmp_11f80_1;
                        uint32_t RAX_73 = sym__rotl32((uint32_t)(stack_m44_2 + (uint32_t)((uint64_t)(int32_t)tmp_11e00_2 * 0x165667b1)), 11);
                        stack_m44_2 = (uint32_t)((uint64_t)(int32_t)RAX_73 * 0xffffffff9e3779b1U);
                        tmp_11f80_1 = stack_m16;
                        stack_m16 = tmp_11f80_1 + 1;
                    }
                }
                {
                    uint32_t tmp_lane_100000d5f_3e_85_1 = (uint32_t)((uint64_t)(int32_t)(stack_m44_2 >> 15 ^ stack_m44_2) * 0xffffffff85ebca77U);
                    uint32_t tmp_lane_100000d5f_85_8f_1 = (uint32_t)((uint64_t)(int32_t)(tmp_lane_100000d5f_3e_85_1 >> 13 ^ tmp_lane_100000d5f_3e_85_1) * 0xffffffffc2b2ae3dU);
                    return tmp_lane_100000d5f_85_8f_1 >> 16 ^ tmp_lane_100000d5f_85_8f_1;
                }
            }
        }
    }
}

