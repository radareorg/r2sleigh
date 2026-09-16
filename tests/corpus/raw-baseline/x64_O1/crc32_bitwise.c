uint32_t sym__crc32_bitwise(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 66 source obligations: 41 rendered, 25 elided, 0 refused; 34 statements rendered */
    {
        uint64_t tmp_70500_1 = RSI_0;
        if (tmp_70500_1 == 0) {
            return 0;
        } else {
            uint64_t RAX_1;
            uint64_t RCX_1;
            uint32_t tmp_lane_100000740_2d_17_1;
            RAX_1 = 0xffffffff;
            RCX_1 = (uint64_t)0;
            for (; ; ) {
                uint64_t RDX_5;
                uint8_t tmp_11e00_2 = ((uint8_t*)RDI_0)[RCX_1];
                uint32_t tmp_lane_100000730_7_6_1 = (uint32_t)tmp_11e00_2 ^ (uint32_t)RAX_1;
                RAX_1 = (uint64_t)(uint32_t)tmp_lane_100000730_7_6_1;
                RDX_5 = 8;
                for (; ; ) {
                    uint32_t tmp_lane_100000740_0_8_1 = (uint32_t)RAX_1;
                    uint32_t tmp_lane_100000740_5_b_1 = tmp_lane_100000740_0_8_1 >> 1;
                    uint32_t tmp_lane_100000740_f_e_1 = (uint32_t)RAX_1 & 1;
                    uint32_t tmp_lane_100000740_19_11_1 = -tmp_lane_100000740_f_e_1;
                    uint32_t tmp_lane_100000740_23_13_1 = tmp_lane_100000740_19_11_1 & 0xedb88320;
                    tmp_lane_100000740_2d_17_1 = tmp_lane_100000740_23_13_1 ^ tmp_lane_100000740_5_b_1;
                    RAX_1 = (uint64_t)(uint32_t)tmp_lane_100000740_2d_17_1;
                    uint32_t tmp_lane_100000740_35_19_1 = (uint32_t)RDX_5;
                    uint32_t tmp_lane_100000740_36_1a_1 = tmp_lane_100000740_35_19_1 - 1;
                    RDX_5 = (uint64_t)(uint32_t)tmp_lane_100000740_36_1a_1;
                    uint8_t tmp_12800_3 = tmp_lane_100000740_36_1a_1 != 0;
                    if (!tmp_12800_3) {
                        break;
                    }
                }
                {
                    RCX_1++;
                    uint64_t tmp_3f080_2 = RCX_1;
                    uint8_t tmp_12800_4 = tmp_3f080_2 != RSI_0;
                    if (!tmp_12800_4) {
                        break;
                    }
                }
            }
            return ~tmp_lane_100000740_2d_17_1;
        }
    }
}

