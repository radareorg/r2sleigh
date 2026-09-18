uint32_t sym__murmur3_32(uint64_t RDI_0, uint64_t RSI_0, uint32_t EDX_0)
{
    /* r2dec proof: no individual construct is marked; 215 source obligations: 185 rendered, 30 elided, 0 refused; 47 statements rendered */
    {
        uint32_t RDX_0_2;
        RDX_0_2 = EDX_0;
        if (RSI_0 >= 4) {
            uint64_t RCX_2;
            uint64_t RAX_1;
            RCX_2 = RSI_0 >> 2;
            if (RCX_2 != 1) {
                RCX_2 &= (uint64_t)-0x2;
                RAX_1 = (uint64_t)0;
                for (; ; ) {
                    int32_t tmp_11f00_2 = (int32_t)*(uint32_t*)(RDI_0 + RAX_1);
                    uint32_t tmp_lane_100000d10_6_6_1 = (uint32_t)((uint64_t)tmp_11f00_2 * 0xffffffffcc9e2d51U);
                    uint32_t tmp_lane_100000d10_2b_d_1 = RDX_0_2 ^ (uint32_t)((uint64_t)(int32_t)(tmp_lane_100000d10_6_6_1 << 15 | tmp_lane_100000d10_6_6_1 >> 17) * 0x1b873593);
                    uint64_t R8_6 = (uint64_t)(tmp_lane_100000d10_2b_d_1 << 13 | tmp_lane_100000d10_2b_d_1 >> 19);
                    int32_t tmp_11f00_3 = (int32_t)*(uint32_t*)(RDI_0 + RAX_1 + 4);
                    uint32_t tmp_lane_100000d10_5c_15_1 = (uint32_t)((uint64_t)tmp_11f00_3 * 0xffffffffcc9e2d51U);
                    uint32_t tmp_lane_100000d10_81_1c_1 = (uint32_t)(R8_6 * 4 + R8_6) - 0x19ab949c ^ (uint32_t)((uint64_t)(int32_t)(tmp_lane_100000d10_5c_15_1 << 15 | tmp_lane_100000d10_5c_15_1 >> 17) * 0x1b873593);
                    uint64_t R8_11 = (uint64_t)(tmp_lane_100000d10_81_1c_1 << 13 | tmp_lane_100000d10_81_1c_1 >> 19);
                    RDX_0_2 = (uint32_t)((uint32_t)(R8_11 * 4 + R8_11) - 0x19ab949c);
                    RAX_1 += 8;
                    RCX_2 -= 2;
                    if (RCX_2 == 0) {
                        break;
                    }
                }
            } else {
                RAX_1 = (uint64_t)0;
            }
            if ((uint8_t)((uint8_t)RSI_0 & 4) != 0) {
                int32_t tmp_11f00_5 = (int32_t)*(uint32_t*)(RDI_0 + RAX_1);
                uint32_t tmp_lane_100000d69_6_25_1 = (uint32_t)((uint64_t)tmp_11f00_5 * 0xffffffffcc9e2d51U);
                uint32_t tmp_lane_100000d69_2b_2c_1 = RDX_0_2 ^ (uint32_t)((uint64_t)(int32_t)(tmp_lane_100000d69_6_25_1 << 15 | tmp_lane_100000d69_6_25_1 >> 17) * 0x1b873593);
                uint64_t RAX_10 = (uint64_t)(tmp_lane_100000d69_2b_2c_1 << 13 | tmp_lane_100000d69_2b_2c_1 >> 19);
                RDX_0_2 = (uint32_t)((uint32_t)(RAX_10 * 4 + RAX_10) - 0x19ab949c);
            }
        }
        {
            uint32_t RCX_8;
            uint64_t RAX_13 = RSI_0 & (uint64_t)-0x4;
            uint32_t tmp_lane_100000d87_e_37_1 = (uint32_t)RSI_0 & 3;
            RCX_8 = (uint32_t)0;
            switch (tmp_lane_100000d87_e_37_1) {
            case 3:
                {
                    uint8_t tmp_11e00_1 = ((uint8_t*)RDI_0)[RAX_13 + 2];
                    RCX_8 = (uint32_t)tmp_11e00_1 << 16;
                }
            case 2:
                {
                    uint8_t tmp_11e00_3 = ((uint8_t*)RDI_0)[RAX_13 + 1];
                    RCX_8 = (uint32_t)((uint32_t)tmp_11e00_3 << 8 | RCX_8);
                }
            case 1:
                {
                    uint8_t tmp_11e00_5 = ((uint8_t*)RDI_0)[RAX_13];
                    uint32_t tmp_lane_100000dbd_12_4e_1 = (uint32_t)((uint64_t)(int32_t)((uint32_t)tmp_11e00_5 ^ RCX_8) * 0xffffffffcc9e2d51U);
                    RDX_0_2 = (uint32_t)(RDX_0_2 ^ (uint32_t)((uint64_t)(int32_t)(tmp_lane_100000dbd_12_4e_1 << 15 | tmp_lane_100000dbd_12_4e_1 >> 17) * 0x1b873593));
                    break;
                }
            case 0:
            default:
                break;
            }
            {
                uint32_t tmp_lane_100000dd4_2_59_1 = (uint32_t)RSI_0 ^ RDX_0_2;
                uint32_t tmp_lane_100000dd4_3f_65_1 = (uint32_t)((uint64_t)(int32_t)(tmp_lane_100000dd4_2_59_1 >> 16 ^ tmp_lane_100000dd4_2_59_1) * 0xffffffff85ebca6bU);
                uint32_t tmp_lane_100000dd4_7a_70_1 = (uint32_t)((uint64_t)(int32_t)(tmp_lane_100000dd4_3f_65_1 >> 13 ^ tmp_lane_100000dd4_3f_65_1) * 0xffffffffc2b2ae35U);
                return tmp_lane_100000dd4_7a_70_1 >> 16 ^ tmp_lane_100000dd4_7a_70_1;
            }
        }
    }
}

