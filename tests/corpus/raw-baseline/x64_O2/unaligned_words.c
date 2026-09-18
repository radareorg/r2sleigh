uint64_t sym__unaligned_words(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 152 source obligations: 116 rendered, 36 elided, 0 refused; 39 statements rendered */
    {
        uint64_t RAX_1;
        uint64_t RCX_1;
        RAX_1 = 0x9e3779b9;
        if (8 <= RSI_0) {
            uint64_t RDX_1;
            RDX_1 = (uint64_t)0;
            for (; ; ) {
                uint32_t tmp_11f00_2 = *(uint32_t*)(RDI_0 + RDX_1 + 1);
                RAX_1 = (uint64_t)(uint32_t)((uint64_t)(int32_t)((uint32_t)RAX_1 ^ tmp_11f00_2) * 0x1000193);
                RCX_1 = RDX_1 + 7;
                uint64_t tmp_3f080_2 = RDX_1 + 15;
                RDX_1 = RCX_1;
                if (RSI_0 < tmp_3f080_2) {
                    break;
                }
            }
        } else {
            RCX_1 = (uint64_t)0;
        }
        {
            uint64_t RDX_7 = RCX_1 - RSI_0;
            if (RCX_1 < RSI_0) {
                uint64_t R8_3;
                uint32_t tmp_lane_100001392_e_12_1 = (uint32_t)RSI_0 - (uint32_t)RCX_1 & 3;
                R8_3 = (uint64_t)tmp_lane_100001392_e_12_1;
                if (tmp_lane_100001392_e_12_1 != 0) {
                    for (; ; ) {
                        uint8_t tmp_11e00_2 = ((uint8_t*)RDI_0)[RCX_1];
                        RAX_1 = (uint64_t)(uint32_t)((uint64_t)(int32_t)((uint32_t)tmp_11e00_2 ^ (uint32_t)RAX_1) * 0x1000193);
                        RCX_1++;
                        R8_3--;
                        if (R8_3 == 0) {
                            break;
                        }
                    }
                }
                if ((uint64_t)-0x4 >= RDX_7) {
                    for (; ; ) {
                        uint8_t tmp_11e00_5 = ((uint8_t*)RDI_0)[RCX_1];
                        uint8_t tmp_11e00_6 = ((uint8_t*)RDI_0)[RCX_1 + 1];
                        uint8_t tmp_11e00_7 = ((uint8_t*)RDI_0)[RCX_1 + 2];
                        uint8_t tmp_11e00_8 = ((uint8_t*)RDI_0)[RCX_1 + 3];
                        RAX_1 = (uint64_t)(uint32_t)((uint64_t)(int32_t)((uint32_t)tmp_11e00_8 ^ (uint32_t)((uint64_t)(int32_t)((uint32_t)tmp_11e00_7 ^ (uint32_t)((uint64_t)(int32_t)((uint32_t)((uint64_t)(int32_t)((uint32_t)tmp_11e00_5 ^ (uint32_t)RAX_1) * 0x1000193) ^ (uint32_t)tmp_11e00_6) * 0x1000193)) * 0x1000193)) * 0x1000193);
                        RCX_1 += 4;
                        if (RSI_0 == RCX_1) {
                            break;
                        }
                    }
                }
            }
            return RAX_1;
        }
    }
}

