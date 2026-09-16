uint32_t sym__xxhash32(uint64_t RDI_0, uint64_t RSI_0, uint32_t EDX_0)
{
    uint32_t sym__rotl32(uint32_t, uint8_t);

    /* r2dec proof: no individual construct is marked; 565 source obligations: 389 rendered, 176 elided, 0 refused; 135 statements rendered */
    {
        uint32_t stack_m44;
        uint64_t stack_m40;
        int32_t stack_m28;
        uint64_t stack_m24;
        uint64_t stack_m16;
        uint64_t tmp_11f80_1;
        uint64_t tmp_11f80_2;
        uint64_t tmp_11f80_6;
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
                int32_t stack_m72;
                int32_t stack_m68;
                int32_t stack_m64;
                int32_t stack_m60;
                uint64_t stack_m56;
                tmp_11f80_6 = stack_m40;
                stack_m56 = tmp_11f80_6 - 16;
                tmp_11f00_1 = (int32_t)stack_m28;
                stack_m60 = (int32_t)((uint32_t)tmp_11f00_1 + 0x24234428);
                tmp_11f00_1 = (int32_t)stack_m28;
                stack_m64 = (int32_t)((uint32_t)tmp_11f00_1 - 0x7a143589);
                tmp_11f00_1 = (int32_t)stack_m28;
                stack_m68 = tmp_11f00_1;
                tmp_11f00_1 = (int32_t)stack_m28;
                stack_m72 = (int32_t)((uint32_t)tmp_11f00_1 + 0x61c8864f);
                for (; ; ) {
                    int32_t stack_m76;
                    tmp_11f80_1 = stack_m16;
                    int32_t tmp_11f00_6 = (int32_t)*(uint32_t*)tmp_11f80_1;
                    stack_m76 = tmp_11f00_6;
                    uint64_t RAX_17 = (uint64_t)sym__rotl32((uint32_t)((uint32_t)((uint64_t)stack_m76 * 0xffffffff85ebca77U) + (uint32_t)stack_m60), 13);
                    stack_m60 = (int32_t)((uint64_t)(int32_t)RAX_17 * 0xffffffff9e3779b1U);
                    tmp_11f80_1 = stack_m16;
                    stack_m16 = tmp_11f80_1 + 4;
                    tmp_11f80_1 = stack_m16;
                    int32_t tmp_11f00_9 = (int32_t)*(uint32_t*)tmp_11f80_1;
                    stack_m76 = tmp_11f00_9;
                    uint64_t RAX_24 = (uint64_t)sym__rotl32((uint32_t)((uint32_t)((uint64_t)stack_m76 * 0xffffffff85ebca77U) + (uint32_t)stack_m64), 13);
                    stack_m64 = (int32_t)((uint64_t)(int32_t)RAX_24 * 0xffffffff9e3779b1U);
                    tmp_11f80_1 = stack_m16;
                    stack_m16 = tmp_11f80_1 + 4;
                    tmp_11f80_1 = stack_m16;
                    int32_t tmp_11f00_12 = (int32_t)*(uint32_t*)tmp_11f80_1;
                    stack_m76 = tmp_11f00_12;
                    uint64_t RAX_31 = (uint64_t)sym__rotl32((uint32_t)((uint32_t)((uint64_t)stack_m76 * 0xffffffff85ebca77U) + (uint32_t)stack_m68), 13);
                    stack_m68 = (int32_t)((uint64_t)(int32_t)RAX_31 * 0xffffffff9e3779b1U);
                    tmp_11f80_1 = stack_m16;
                    stack_m16 = tmp_11f80_1 + 4;
                    tmp_11f80_1 = stack_m16;
                    int32_t tmp_11f00_15 = (int32_t)*(uint32_t*)tmp_11f80_1;
                    stack_m76 = tmp_11f00_15;
                    uint64_t RAX_38 = (uint64_t)sym__rotl32((uint32_t)((uint32_t)((uint64_t)stack_m76 * 0xffffffff85ebca77U) + (uint32_t)stack_m72), 13);
                    stack_m72 = (int32_t)((uint64_t)(int32_t)RAX_38 * 0xffffffff9e3779b1U);
                    tmp_11f80_1 = stack_m16;
                    stack_m16 = tmp_11f80_1 + 4;
                    tmp_11f80_1 = stack_m16;
                    uint64_t tmp_3f800_2 = stack_m56;
                    uint8_t tmp_12900_2 = tmp_11f80_1 <= tmp_3f800_2;
                    if (!tmp_12900_2) {
                        break;
                    }
                }
                {
                    uint32_t stack_m92;
                    uint32_t stack_m88;
                    int32_t stack_m84;
                    uint64_t RAX_43 = (uint64_t)sym__rotl32((uint32_t)stack_m60, 1);
                    stack_m92 = (uint32_t)RAX_43;
                    uint64_t RAX_44 = (uint64_t)sym__rotl32((uint32_t)stack_m64, 7);
                    uint32_t tmp_lane_100000c70_13_44_1 = (uint32_t)RAX_44;
                    stack_m88 = stack_m92 + tmp_lane_100000c70_13_44_1;
                    uint64_t RAX_47 = (uint64_t)sym__rotl32((uint32_t)stack_m68, 12);
                    uint32_t tmp_lane_100000c70_2e_4d_1 = (uint32_t)RAX_47;
                    stack_m84 = (int32_t)(stack_m88 + tmp_lane_100000c70_2e_4d_1);
                    uint64_t RAX_50 = (uint64_t)sym__rotl32((uint32_t)stack_m72, 18);
                    uint32_t tmp_lane_100000c70_49_56_1 = (uint32_t)RAX_50;
                    stack_m44 = (uint32_t)stack_m84 + tmp_lane_100000c70_49_56_1;
                }
            }
        }
        {
            uint32_t tmp_11f00_27;
            tmp_11f80_2 = stack_m24;
            tmp_11f00_27 = stack_m44;
            tmp_11f00_27 = stack_m44;
            tmp_11f00_27 = stack_m44;
            stack_m44 = (uint32_t)tmp_11f80_2 + tmp_11f00_27;
            for (; ; ) {
                tmp_11f80_1 = stack_m16;
                uint64_t RAX_60 = tmp_11f80_1 + 4;
                tmp_11f80_6 = stack_m40;
                uint64_t tmp_3f800_5 = tmp_11f80_6;
                uint8_t tmp_12a80_2 = tmp_3f800_5 < RAX_60;
                if (tmp_12a80_2) {
                    break;
                } else {
                    uint32_t stack_m80;
                    tmp_11f80_1 = stack_m16;
                    uint32_t tmp_11f00_31 = *(uint32_t*)tmp_11f80_1;
                    stack_m80 = tmp_11f00_31;
                    tmp_11f00_27 = stack_m44;
                    uint64_t RAX_64 = (uint64_t)sym__rotl32((uint32_t)((uint32_t)((uint64_t)(int32_t)stack_m80 * 0xffffffffc2b2ae3dU) + tmp_11f00_27), 17);
                    stack_m44 = (uint32_t)((uint64_t)(int32_t)RAX_64 * 0x27d4eb2f);
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
                        tmp_11f00_27 = stack_m44;
                        tmp_11f80_1 = stack_m16;
                        uint8_t tmp_11e00_2 = *(uint8_t*)tmp_11f80_1;
                        uint64_t RAX_73 = (uint64_t)sym__rotl32((uint32_t)((uint32_t)((uint64_t)(int32_t)tmp_11e00_2 * 0x165667b1) + tmp_11f00_27), 11);
                        stack_m44 = (uint32_t)((uint64_t)(int32_t)RAX_73 * 0xffffffff9e3779b1U);
                        tmp_11f80_1 = stack_m16;
                        stack_m16 = tmp_11f80_1 + 1;
                    }
                }
                {
                    tmp_11f00_27 = stack_m44;
                    tmp_11f00_27 = stack_m44;
                    stack_m44 = tmp_11f00_27 >> 15 ^ tmp_11f00_27;
                    tmp_11f00_27 = stack_m44;
                    stack_m44 = (uint32_t)((uint64_t)(int32_t)tmp_11f00_27 * 0xffffffff85ebca77U);
                    tmp_11f00_27 = stack_m44;
                    tmp_11f00_27 = stack_m44;
                    stack_m44 = tmp_11f00_27 >> 13 ^ tmp_11f00_27;
                    tmp_11f00_27 = stack_m44;
                    stack_m44 = (uint32_t)((uint64_t)(int32_t)tmp_11f00_27 * 0xffffffffc2b2ae3dU);
                    tmp_11f00_27 = stack_m44;
                    tmp_11f00_27 = stack_m44;
                    stack_m44 = tmp_11f00_27 >> 16 ^ tmp_11f00_27;
                    tmp_11f00_27 = stack_m44;
                    return tmp_11f00_27;
                }
            }
        }
    }
}

