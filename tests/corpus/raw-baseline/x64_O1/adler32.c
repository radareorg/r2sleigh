uint64_t sym__adler32(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 77 source obligations: 55 rendered, 22 elided, 0 refused; 44 statements rendered */
    {
        uint64_t tmp_70500_1 = RSI_0;
        if (tmp_70500_1 == 0) {
            uint64_t RAX_7 = 1;
            return RAX_7;
        } else {
            uint64_t R8_1;
            uint64_t RCX_1;
            uint64_t RAX_1;
            uint32_t tmp_lane_100000650_49_11_1;
            uint32_t tmp_lane_100000650_94_1b_1;
            R8_1 = 1;
            RCX_1 = (uint64_t)0;
            RAX_1 = (uint64_t)0;
            for (; ; ) {
                int64_t R9_3;
                int64_t R9_7;
                uint8_t tmp_11e00_2 = ((uint8_t*)RDI_0)[RCX_1];
                uint32_t tmp_lane_100000650_3_6_1 = (uint32_t)tmp_11e00_2;
                uint32_t tmp_lane_100000650_5_8_1 = (uint32_t)R8_1;
                uint32_t tmp_lane_100000650_7_9_1 = tmp_lane_100000650_3_6_1 + tmp_lane_100000650_5_8_1;
                R9_3 = (int64_t)(uint32_t)tmp_lane_100000650_7_9_1;
                R9_3 = (int64_t)((uint64_t)R9_3 * 0x80078071);
                R9_3 = (int64_t)((uint64_t)R9_3 >> 47);
                uint64_t tmp_4c780_2 = (uint64_t)(int32_t)R9_3 * 0xfff1;
                int32_t tmp_lane_100000650_41_e_1 = (int32_t)tmp_4c780_2;
                tmp_lane_100000650_49_11_1 = tmp_lane_100000650_7_9_1 - (uint32_t)tmp_lane_100000650_41_e_1;
                R8_1 = (uint64_t)(uint32_t)tmp_lane_100000650_49_11_1;
                uint32_t tmp_lane_100000650_51_13_1 = (uint32_t)RAX_1;
                uint32_t tmp_lane_100000650_53_15_1 = tmp_lane_100000650_51_13_1 + tmp_lane_100000650_49_11_1;
                R9_7 = (int64_t)tmp_lane_100000650_53_15_1;
                R9_7 = (int64_t)((uint64_t)R9_7 * 0x80078071);
                R9_7 = (int64_t)((uint64_t)R9_7 >> 47);
                uint64_t tmp_4c780_3 = (uint64_t)(int32_t)R9_7 * 0xfff1;
                int32_t tmp_lane_100000650_8c_18_1 = (int32_t)tmp_4c780_3;
                tmp_lane_100000650_94_1b_1 = tmp_lane_100000650_53_15_1 - (uint32_t)tmp_lane_100000650_8c_18_1;
                RAX_1 = (uint64_t)(uint32_t)tmp_lane_100000650_94_1b_1;
                RCX_1++;
                uint64_t tmp_3f080_2 = RSI_0;
                uint8_t ZF_12 = tmp_3f080_2 == RCX_1;
                if (ZF_12) {
                    break;
                }
            }
            {
                uint32_t tmp_lane_10000068d_2_1e_1 = tmp_lane_100000650_94_1b_1 << 16;
                uint32_t tmp_lane_10000068d_28_22_1 = tmp_lane_10000068d_2_1e_1 | tmp_lane_100000650_49_11_1;
                uint64_t RAX_6 = (uint64_t)(uint32_t)tmp_lane_10000068d_28_22_1;
                return RAX_6;
            }
        }
    }
}

