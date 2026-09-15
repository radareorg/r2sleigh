uint64_t sym__unaligned_words(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 80 source obligations: 56 rendered, 24 elided, 0 refused; 40 statements rendered */
    {
        uint64_t RAX_1;
        uint64_t RCX_1;
        RAX_1 = 0x9e3779b9;
        uint64_t tmp_3ea80_1 = RSI_0;
        if (8 <= tmp_3ea80_1) {
            uint64_t RDX_1;
            RDX_1 = (uint64_t)0;
            for (; ; ) {
                uint32_t tmp_11f00_2 = *(uint32_t*)(RDI_0 + RDX_1 + 1);
                int32_t tmp_lane_100000d50_6_7_1 = (int32_t)((uint32_t)RAX_1 ^ tmp_11f00_2);
                uint64_t tmp_4c780_2 = (uint64_t)tmp_lane_100000d50_6_7_1 * 0x1000193;
                int32_t tmp_lane_100000d50_11_a_1 = (int32_t)tmp_4c780_2;
                RAX_1 = (uint64_t)(uint32_t)tmp_lane_100000d50_11_a_1;
                uint64_t RCX_3 = RDX_1 + 7;
                RDX_1 += 15;
                uint64_t tmp_3f080_2 = RDX_1;
                uint8_t CF_8 = tmp_3f080_2 < RSI_0;
                uint8_t ZF_7 = tmp_3f080_2 == RSI_0;
                uint64_t RDX_4 = RCX_3;
                RDX_1 = RDX_4;
                RCX_1 = RCX_3;
                if (!(CF_8 || ZF_7)) {
                    break;
                }
            }
        } else {
            RCX_1 = (uint64_t)0;
        }
        {
            uint64_t tmp_3f080_4 = RCX_1;
            uint8_t CF_10 = tmp_3f080_4 < RSI_0;
            if (CF_10) {
                for (; ; ) {
                    uint8_t tmp_11e00_2 = ((uint8_t*)RDI_0)[RCX_1];
                    uint32_t tmp_lane_100000d70_3_b_1 = (uint32_t)tmp_11e00_2;
                    int32_t tmp_lane_100000d70_7_e_1 = (int32_t)((uint32_t)RAX_1 ^ tmp_lane_100000d70_3_b_1);
                    uint64_t tmp_4c780_5 = (uint64_t)tmp_lane_100000d70_7_e_1 * 0x1000193;
                    int32_t tmp_lane_100000d70_12_11_1 = (int32_t)tmp_4c780_5;
                    RAX_1 = (uint64_t)(uint32_t)tmp_lane_100000d70_12_11_1;
                    RCX_1++;
                    uint64_t tmp_3f080_6 = RSI_0;
                    uint8_t ZF_13 = tmp_3f080_6 == RCX_1;
                    if (ZF_13) {
                        break;
                    }
                }
            }
            return RAX_1;
        }
    }
}

