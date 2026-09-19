uint32_t sym__murmur3_32(uint64_t RDI_0, uint64_t RSI_0, uint32_t EDX_0)
{
    /* r2dec proof: no individual construct is marked; 140 source obligations: 117 rendered, 23 elided, 0 refused; 32 statements rendered */
    {
        uint32_t RDX_0_2;
        RDX_0_2 = EDX_0;
        if (RSI_0 >= 4) {
            uint64_t RCX_1;
            uint64_t RAX_2 = RSI_0 >> 2;
            RCX_1 = (uint64_t)0;
            for (; ; ) {
                int32_t tmp_11f00_2 = (int32_t)((uint32_t*)RDI_0)[RCX_1];
                uint32_t tmp_lane_100000830_6_3_1 = (uint32_t)((uint64_t)tmp_11f00_2 * 0xffffffffcc9e2d51U);
                uint32_t tmp_lane_100000830_2b_a_1 = RDX_0_2 ^ (uint32_t)((uint64_t)(int32_t)(tmp_lane_100000830_6_3_1 << 15 | tmp_lane_100000830_6_3_1 >> 17) * 0x1b873593);
                uint64_t R8_6 = (uint64_t)(tmp_lane_100000830_2b_a_1 << 13 | tmp_lane_100000830_2b_a_1 >> 19);
                RDX_0_2 = (uint32_t)((uint32_t)(R8_6 * 4 + R8_6) - 0x19ab949c);
                RCX_1++;
                if (RAX_2 == RCX_1) {
                    break;
                }
            }
        }
        {
            uint32_t RCX_5;
            uint64_t RAX_5 = RSI_0 & (uint64_t)-0x4;
            uint32_t tmp_lane_10000085c_e_15_1 = (uint32_t)RSI_0 & 3;
            RCX_5 = (uint32_t)0;
            switch (tmp_lane_10000085c_e_15_1) {
            case 3:
                {
                    uint8_t tmp_11e00_1 = ((uint8_t*)RDI_0)[RAX_5 + 2];
                    RCX_5 = (uint32_t)tmp_11e00_1 << 16;
                }
            case 2:
                {
                    uint8_t tmp_11e00_3 = ((uint8_t*)RDI_0)[RAX_5 + 1];
                    RCX_5 = (uint32_t)((uint32_t)tmp_11e00_3 << 8 | RCX_5);
                }
            case 1:
                {
                    uint8_t tmp_11e00_5 = ((uint8_t*)RDI_0)[RAX_5];
                    uint32_t tmp_lane_100000892_12_2c_1 = (uint32_t)((uint64_t)(int32_t)((uint32_t)tmp_11e00_5 ^ RCX_5) * 0xffffffffcc9e2d51U);
                    RDX_0_2 = (uint32_t)(RDX_0_2 ^ (uint32_t)((uint64_t)(int32_t)(tmp_lane_100000892_12_2c_1 << 15 | tmp_lane_100000892_12_2c_1 >> 17) * 0x1b873593));
                    break;
                }
            case 0:
            default:
                break;
            }
            {
                uint32_t tmp_lane_1000008a9_2_37_1 = (uint32_t)RSI_0 ^ RDX_0_2;
                uint32_t tmp_lane_1000008a9_3f_43_1 = (uint32_t)((uint64_t)(int32_t)(tmp_lane_1000008a9_2_37_1 >> 16 ^ tmp_lane_1000008a9_2_37_1) * 0xffffffff85ebca6bU);
                uint32_t tmp_lane_1000008a9_7a_4e_1 = (uint32_t)((uint64_t)(int32_t)(tmp_lane_1000008a9_3f_43_1 >> 13 ^ tmp_lane_1000008a9_3f_43_1) * 0xffffffffc2b2ae35U);
                return tmp_lane_1000008a9_7a_4e_1 >> 16 ^ tmp_lane_1000008a9_7a_4e_1;
            }
        }
    }
}

