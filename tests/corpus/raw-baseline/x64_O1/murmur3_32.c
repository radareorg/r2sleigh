uint32_t sym__murmur3_32(uint64_t RDI_0, uint64_t RSI_0, uint32_t EDX_0)
{
    /* r2dec proof: no individual construct is marked; 143 source obligations: 119 rendered, 24 elided, 0 refused; 70 statements rendered */
    {
        uint64_t RDX_0_2;
        RDX_0_2 = (uint64_t)(uint32_t)EDX_0;
        uint64_t tmp_3ea80_1 = RSI_0;
        uint8_t CF_1 = tmp_3ea80_1 < 4;
        if (!CF_1) {
            uint64_t RAX_1;
            uint64_t RCX_1;
            RAX_1 = RSI_0;
            RAX_1 >>= 2;
            RCX_1 = (uint64_t)0;
            for (; ; ) {
                int32_t tmp_11f00_2 = (int32_t)((uint32_t*)RDI_0)[RCX_1];
                uint64_t tmp_4c780_2 = (uint64_t)tmp_11f00_2 * 0xffffffffcc9e2d51U;
                uint32_t tmp_lane_100000830_6_3_1 = (uint32_t)tmp_4c780_2;
                int32_t tmp_lane_100000830_10_5_1 = (int32_t)(tmp_lane_100000830_6_3_1 << 15 | tmp_lane_100000830_6_3_1 >> 17);
                uint64_t tmp_4c780_3 = (uint64_t)tmp_lane_100000830_10_5_1 * 0x1b873593;
                int32_t tmp_lane_100000830_23_7_1 = (int32_t)tmp_4c780_3;
                uint32_t tmp_lane_100000830_2b_a_1 = (uint32_t)RDX_0_2 ^ (uint32_t)tmp_lane_100000830_23_7_1;
                uint32_t tmp_lane_100000830_37_d_1 = tmp_lane_100000830_2b_a_1 << 13 | tmp_lane_100000830_2b_a_1 >> 19;
                uint64_t R8_6 = (uint64_t)(uint32_t)tmp_lane_100000830_37_d_1;
                uint32_t tmp_lane_100000830_49_e_1 = (uint32_t)(R8_6 * 4 + R8_6);
                uint32_t tmp_lane_100000830_4d_10_1 = tmp_lane_100000830_49_e_1 - 0x19ab949c;
                RDX_0_2 = (uint64_t)(uint32_t)tmp_lane_100000830_4d_10_1;
                RCX_1++;
                uint64_t tmp_3f080_2 = RAX_1;
                uint8_t ZF_8 = tmp_3f080_2 == RCX_1;
                if (ZF_8) {
                    break;
                }
            }
        }
        {
            uint64_t RCX_7;
            uint64_t RCX_9;
            uint64_t RDX_5;
            uint64_t RAX_5 = RSI_0 & (uint64_t)-0x4;
            uint32_t tmp_lane_10000085c_a_12_1 = (uint32_t)RSI_0;
            uint32_t tmp_lane_10000085c_e_15_1 = tmp_lane_10000085c_a_12_1 & 3;
            RCX_7 = 0;
            RCX_9 = 0;
            RDX_5 = RDX_0_2;
            switch (tmp_lane_10000085c_e_15_1) {
            case 3:
                {
                    uint8_t tmp_11e00_1 = ((uint8_t*)RDI_0)[RAX_5 + 2];
                    uint32_t tmp_lane_10000087d_4_1a_1 = (uint32_t)tmp_11e00_1;
                    uint32_t tmp_lane_10000087d_8_1c_1 = tmp_lane_10000087d_4_1a_1 << 16;
                    RCX_7 = (uint64_t)(uint32_t)tmp_lane_10000087d_8_1c_1;
                }
            case 2:
                {
                    uint8_t tmp_11e00_3 = ((uint8_t*)RDI_0)[RAX_5 + 1];
                    uint32_t tmp_lane_100000885_4_1e_1 = (uint32_t)tmp_11e00_3;
                    uint32_t tmp_lane_100000885_8_20_1 = tmp_lane_100000885_4_1e_1 << 8;
                    uint32_t tmp_lane_100000885_2e_24_1 = (uint32_t)RCX_7 | tmp_lane_100000885_8_20_1;
                    RCX_9 = (uint64_t)(uint32_t)tmp_lane_100000885_2e_24_1;
                }
            case 1:
                {
                    uint8_t tmp_11e00_5 = ((uint8_t*)RDI_0)[RAX_5];
                    uint32_t tmp_lane_100000892_3_26_1 = (uint32_t)tmp_11e00_5;
                    int32_t tmp_lane_100000892_7_29_1 = (int32_t)((uint32_t)RCX_9 ^ tmp_lane_100000892_3_26_1);
                    uint64_t tmp_4c780_5 = (uint64_t)tmp_lane_100000892_7_29_1 * 0xffffffffcc9e2d51U;
                    uint32_t tmp_lane_100000892_12_2c_1 = (uint32_t)tmp_4c780_5;
                    int32_t tmp_lane_100000892_1c_2e_1 = (int32_t)(tmp_lane_100000892_12_2c_1 << 15 | tmp_lane_100000892_12_2c_1 >> 17);
                    uint64_t tmp_4c780_6 = (uint64_t)tmp_lane_100000892_1c_2e_1 * 0x1b873593;
                    int32_t tmp_lane_100000892_2f_30_1 = (int32_t)tmp_4c780_6;
                    uint32_t tmp_lane_100000892_37_33_1 = (uint32_t)RDX_0_2 ^ (uint32_t)tmp_lane_100000892_2f_30_1;
                    RDX_5 = (uint64_t)(uint32_t)tmp_lane_100000892_37_33_1;
                    break;
                }
            case 0:
            default:
                break;
            }
            {
                uint32_t tmp_lane_1000008a9_2_37_1 = (uint32_t)RSI_0 ^ (uint32_t)RDX_5;
                uint32_t tmp_lane_1000008a9_e_3c_1 = tmp_lane_1000008a9_2_37_1 >> 16;
                int32_t tmp_lane_1000008a9_34_40_1 = (int32_t)(tmp_lane_1000008a9_e_3c_1 ^ tmp_lane_1000008a9_2_37_1);
                uint64_t tmp_4c780_8 = (uint64_t)tmp_lane_1000008a9_34_40_1 * 0xffffffff85ebca6bU;
                uint32_t tmp_lane_1000008a9_3f_43_1 = (uint32_t)tmp_4c780_8;
                uint32_t tmp_lane_1000008a9_49_47_1 = tmp_lane_1000008a9_3f_43_1 >> 13;
                int32_t tmp_lane_1000008a9_6f_4b_1 = (int32_t)(tmp_lane_1000008a9_49_47_1 ^ tmp_lane_1000008a9_3f_43_1);
                uint64_t tmp_4c780_9 = (uint64_t)tmp_lane_1000008a9_6f_4b_1 * 0xffffffffc2b2ae35U;
                uint32_t tmp_lane_1000008a9_7a_4e_1 = (uint32_t)tmp_4c780_9;
                uint32_t tmp_lane_1000008a9_84_52_1 = tmp_lane_1000008a9_7a_4e_1 >> 16;
                uint32_t tmp_lane_1000008a9_aa_56_1 = tmp_lane_1000008a9_84_52_1 ^ tmp_lane_1000008a9_7a_4e_1;
                return tmp_lane_1000008a9_aa_56_1;
            }
        }
    }
}

