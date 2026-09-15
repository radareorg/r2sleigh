uint64_t sym__unaligned_words(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 159 source obligations: 124 rendered, 35 elided, 0 refused; 77 statements rendered */
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
                int32_t tmp_lane_100001370_6_7_1 = (int32_t)((uint32_t)RAX_1 ^ tmp_11f00_2);
                uint64_t tmp_4c780_2 = (uint64_t)tmp_lane_100001370_6_7_1 * 0x1000193;
                int32_t tmp_lane_100001370_11_a_1 = (int32_t)tmp_4c780_2;
                RAX_1 = (uint64_t)(uint32_t)tmp_lane_100001370_11_a_1;
                uint64_t RCX_3 = RDX_1 + 7;
                RDX_1 += 15;
                uint64_t tmp_3f080_2 = RDX_1;
                uint64_t RDX_4 = RCX_3;
                uint8_t tmp_12900_2 = tmp_3f080_2 <= RSI_0;
                RDX_1 = RDX_4;
                RCX_1 = RCX_3;
                if (!tmp_12900_2) {
                    break;
                }
            }
        } else {
            RCX_1 = (uint64_t)0;
        }
        {
            uint64_t RAX_14;
            uint64_t RDX_6 = RCX_1;
            uint8_t CF_10 = RDX_6 < RSI_0;
            uint64_t RDX_7 = RDX_6 - RSI_0;
            uint8_t tmp_12700_2 = !CF_10;
            RAX_14 = RAX_1;
            if (!tmp_12700_2) {
                uint64_t R8_4;
                uint32_t tmp_lane_100001392_4_f_1 = (uint32_t)RSI_0 - (uint32_t)RCX_1;
                uint32_t tmp_lane_100001392_e_12_1 = tmp_lane_100001392_4_f_1 & 3;
                uint64_t R8_3 = (uint64_t)(uint32_t)tmp_lane_100001392_e_12_1;
                R8_4 = R8_3;
                if (tmp_lane_100001392_e_12_1 != 0) {
                    for (; ; ) {
                        uint8_t tmp_11e00_2 = ((uint8_t*)RDI_0)[RCX_1];
                        int32_t tmp_lane_1000013a0_7_17_1 = (int32_t)((uint32_t)tmp_11e00_2 ^ (uint32_t)RAX_1);
                        uint64_t tmp_4c780_5 = (uint64_t)tmp_lane_1000013a0_7_17_1 * 0x1000193;
                        int32_t tmp_lane_1000013a0_12_1a_1 = (int32_t)tmp_4c780_5;
                        RAX_1 = (uint64_t)(uint32_t)tmp_lane_1000013a0_12_1a_1;
                        RCX_1++;
                        uint64_t R8_5 = R8_4 - 1;
                        uint8_t tmp_12800_2 = R8_4 != 1;
                        R8_4 = R8_5;
                        if (!tmp_12800_2) {
                            break;
                        }
                    }
                }
                {
                    uint64_t tmp_3ea80_2 = RDX_7;
                    uint8_t tmp_12a80_1 = (uint64_t)-0x4 < tmp_3ea80_2;
                    RAX_14 = RAX_1;
                    if (!tmp_12a80_1) {
                        for (; ; ) {
                            uint8_t tmp_11e00_5 = ((uint8_t*)RDI_0)[RCX_1];
                            int32_t tmp_lane_1000013c0_7_1e_1 = (int32_t)((uint32_t)tmp_11e00_5 ^ (uint32_t)RAX_1);
                            uint64_t tmp_4c780_8 = (uint64_t)tmp_lane_1000013c0_7_1e_1 * 0x1000193;
                            int32_t tmp_lane_1000013c0_12_21_1 = (int32_t)tmp_4c780_8;
                            uint8_t tmp_11e00_6 = ((uint8_t*)RDI_0)[RCX_1 + 1];
                            int32_t tmp_lane_1000013c0_20_25_1 = (int32_t)((uint32_t)tmp_11e00_6 ^ (uint32_t)tmp_lane_1000013c0_12_21_1);
                            uint64_t tmp_4c780_9 = (uint64_t)tmp_lane_1000013c0_20_25_1 * 0x1000193;
                            int32_t tmp_lane_1000013c0_2b_28_1 = (int32_t)tmp_4c780_9;
                            uint8_t tmp_11e00_7 = ((uint8_t*)RDI_0)[RCX_1 + 2];
                            int32_t tmp_lane_1000013c0_39_2c_1 = (int32_t)((uint32_t)tmp_11e00_7 ^ (uint32_t)tmp_lane_1000013c0_2b_28_1);
                            uint64_t tmp_4c780_10 = (uint64_t)tmp_lane_1000013c0_39_2c_1 * 0x1000193;
                            int32_t tmp_lane_1000013c0_44_2f_1 = (int32_t)tmp_4c780_10;
                            uint8_t tmp_11e00_8 = ((uint8_t*)RDI_0)[RCX_1 + 3];
                            int32_t tmp_lane_1000013c0_52_33_1 = (int32_t)((uint32_t)tmp_11e00_8 ^ (uint32_t)tmp_lane_1000013c0_44_2f_1);
                            uint64_t tmp_4c780_11 = (uint64_t)tmp_lane_1000013c0_52_33_1 * 0x1000193;
                            int32_t tmp_lane_1000013c0_5d_36_1 = (int32_t)tmp_4c780_11;
                            RAX_1 = (uint64_t)(uint32_t)tmp_lane_1000013c0_5d_36_1;
                            RCX_1 += 4;
                            uint64_t tmp_3f080_5 = RSI_0;
                            uint8_t tmp_12800_5 = tmp_3f080_5 != RCX_1;
                            RAX_14 = RAX_1;
                            if (!tmp_12800_5) {
                                break;
                            }
                        }
                    }
                }
            }
            return RAX_14;
        }
    }
}

