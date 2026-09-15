uint32_t sym__murmur3_32(uint64_t RDI_0, uint64_t RSI_0, uint32_t EDX_0)
{
    /* r2dec proof: no individual construct is marked; 220 source obligations: 190 rendered, 30 elided, 0 refused; 101 statements rendered */
    {
        uint64_t RDX_0_2;
        uint64_t RDX_8;
        RDX_0_2 = (uint64_t)(uint32_t)EDX_0;
        uint64_t tmp_3ea80_1 = RSI_0;
        uint8_t CF_1 = tmp_3ea80_1 < 4;
        RDX_8 = RDX_0_2;
        if (!CF_1) {
            uint64_t RCX_1;
            uint64_t RAX_1;
            RCX_1 = RSI_0;
            RCX_1 >>= 2;
            uint64_t tmp_3ea80_2 = RCX_1;
            if (tmp_3ea80_2 != 1) {
                uint64_t RAX_2;
                RCX_1 &= (uint64_t)-0x2;
                RAX_2 = (uint64_t)0;
                for (; ; ) {
                    int32_t tmp_11f00_2 = (int32_t)*(uint32_t*)(RAX_2 + RDI_0);
                    uint64_t tmp_4c780_2 = (uint64_t)tmp_11f00_2 * 0xffffffffcc9e2d51U;
                    uint32_t tmp_lane_100000d10_6_6_1 = (uint32_t)tmp_4c780_2;
                    int32_t tmp_lane_100000d10_10_8_1 = (int32_t)(tmp_lane_100000d10_6_6_1 << 15 | tmp_lane_100000d10_6_6_1 >> 17);
                    uint64_t tmp_4c780_3 = (uint64_t)tmp_lane_100000d10_10_8_1 * 0x1b873593;
                    int32_t tmp_lane_100000d10_23_a_1 = (int32_t)tmp_4c780_3;
                    uint32_t tmp_lane_100000d10_2b_d_1 = (uint32_t)RDX_0_2 ^ (uint32_t)tmp_lane_100000d10_23_a_1;
                    uint32_t tmp_lane_100000d10_37_10_1 = tmp_lane_100000d10_2b_d_1 << 13 | tmp_lane_100000d10_2b_d_1 >> 19;
                    uint64_t R8_6 = (uint64_t)(uint32_t)tmp_lane_100000d10_37_10_1;
                    uint32_t tmp_lane_100000d10_4d_13_1 = (uint32_t)(R8_6 * 4 + R8_6) - 0x19ab949c;
                    int32_t tmp_11f00_3 = (int32_t)*(uint32_t*)(RDI_0 + RAX_2 + 4);
                    uint64_t tmp_4c780_4 = (uint64_t)tmp_11f00_3 * 0xffffffffcc9e2d51U;
                    uint32_t tmp_lane_100000d10_5c_15_1 = (uint32_t)tmp_4c780_4;
                    int32_t tmp_lane_100000d10_66_17_1 = (int32_t)(tmp_lane_100000d10_5c_15_1 << 15 | tmp_lane_100000d10_5c_15_1 >> 17);
                    uint64_t tmp_4c780_5 = (uint64_t)tmp_lane_100000d10_66_17_1 * 0x1b873593;
                    int32_t tmp_lane_100000d10_79_19_1 = (int32_t)tmp_4c780_5;
                    uint32_t tmp_lane_100000d10_81_1c_1 = (uint32_t)tmp_lane_100000d10_79_19_1 ^ tmp_lane_100000d10_4d_13_1;
                    uint32_t tmp_lane_100000d10_8d_1f_1 = tmp_lane_100000d10_81_1c_1 << 13 | tmp_lane_100000d10_81_1c_1 >> 19;
                    uint64_t R8_11 = (uint64_t)(uint32_t)tmp_lane_100000d10_8d_1f_1;
                    uint32_t tmp_lane_100000d10_a3_22_1 = (uint32_t)(R8_11 * 4 + R8_11) - 0x19ab949c;
                    RDX_0_2 = (uint64_t)(uint32_t)tmp_lane_100000d10_a3_22_1;
                    RAX_2 += 8;
                    RCX_1 -= 2;
                    uint8_t tmp_12800_3 = RCX_1 != 0;
                    RAX_1 = RAX_2;
                    if (!tmp_12800_3) {
                        break;
                    }
                }
            } else {
                RAX_1 = (uint64_t)0;
            }
            {
                uint8_t tmp_6fe00_1 = (uint8_t)((uint8_t)RSI_0 & 4);
                uint8_t ZF_15 = tmp_6fe00_1 == 0;
                RDX_8 = RDX_0_2;
                if (!ZF_15) {
                    int32_t tmp_11f00_5 = (int32_t)*(uint32_t*)(RAX_1 + RDI_0);
                    uint64_t tmp_4c780_7 = (uint64_t)tmp_11f00_5 * 0xffffffffcc9e2d51U;
                    uint32_t tmp_lane_100000d69_6_25_1 = (uint32_t)tmp_4c780_7;
                    int32_t tmp_lane_100000d69_10_27_1 = (int32_t)(tmp_lane_100000d69_6_25_1 << 15 | tmp_lane_100000d69_6_25_1 >> 17);
                    uint64_t tmp_4c780_8 = (uint64_t)tmp_lane_100000d69_10_27_1 * 0x1b873593;
                    int32_t tmp_lane_100000d69_23_29_1 = (int32_t)tmp_4c780_8;
                    uint32_t tmp_lane_100000d69_2b_2c_1 = (uint32_t)RDX_0_2 ^ (uint32_t)tmp_lane_100000d69_23_29_1;
                    uint32_t tmp_lane_100000d69_37_2f_1 = tmp_lane_100000d69_2b_2c_1 << 13 | tmp_lane_100000d69_2b_2c_1 >> 19;
                    uint64_t RAX_10 = (uint64_t)(uint32_t)tmp_lane_100000d69_37_2f_1;
                    uint32_t tmp_lane_100000d69_49_30_1 = (uint32_t)(RAX_10 * 4 + RAX_10);
                    uint32_t tmp_lane_100000d69_4d_32_1 = tmp_lane_100000d69_49_30_1 - 0x19ab949c;
                    RDX_8 = (uint64_t)(uint32_t)tmp_lane_100000d69_4d_32_1;
                }
            }
        }
        {
            uint64_t RCX_10;
            uint64_t RCX_12;
            uint64_t RDX_10;
            uint64_t RAX_13 = RSI_0 & (uint64_t)-0x4;
            uint32_t tmp_lane_100000d87_e_37_1 = (uint32_t)RSI_0 & 3;
            RCX_10 = 0;
            RCX_12 = 0;
            RDX_10 = RDX_8;
            switch (tmp_lane_100000d87_e_37_1) {
            case 3:
                {
                    uint8_t tmp_11e00_1 = ((uint8_t*)RDI_0)[RAX_13 + 2];
                    uint32_t tmp_lane_100000da8_4_3c_1 = (uint32_t)tmp_11e00_1;
                    uint32_t tmp_lane_100000da8_8_3e_1 = tmp_lane_100000da8_4_3c_1 << 16;
                    RCX_10 = (uint64_t)(uint32_t)tmp_lane_100000da8_8_3e_1;
                }
            case 2:
                {
                    uint8_t tmp_11e00_3 = ((uint8_t*)RDI_0)[RAX_13 + 1];
                    uint32_t tmp_lane_100000db0_4_40_1 = (uint32_t)tmp_11e00_3;
                    uint32_t tmp_lane_100000db0_8_42_1 = tmp_lane_100000db0_4_40_1 << 8;
                    uint32_t tmp_lane_100000db0_2e_46_1 = (uint32_t)RCX_10 | tmp_lane_100000db0_8_42_1;
                    RCX_12 = (uint64_t)(uint32_t)tmp_lane_100000db0_2e_46_1;
                }
            case 1:
                {
                    uint8_t tmp_11e00_5 = ((uint8_t*)RDI_0)[RAX_13];
                    int32_t tmp_lane_100000dbd_7_4b_1 = (int32_t)((uint32_t)tmp_11e00_5 ^ (uint32_t)RCX_12);
                    uint64_t tmp_4c780_10 = (uint64_t)tmp_lane_100000dbd_7_4b_1 * 0xffffffffcc9e2d51U;
                    uint32_t tmp_lane_100000dbd_12_4e_1 = (uint32_t)tmp_4c780_10;
                    int32_t tmp_lane_100000dbd_1c_50_1 = (int32_t)(tmp_lane_100000dbd_12_4e_1 << 15 | tmp_lane_100000dbd_12_4e_1 >> 17);
                    uint64_t tmp_4c780_11 = (uint64_t)tmp_lane_100000dbd_1c_50_1 * 0x1b873593;
                    int32_t tmp_lane_100000dbd_2f_52_1 = (int32_t)tmp_4c780_11;
                    uint32_t tmp_lane_100000dbd_37_55_1 = (uint32_t)RDX_8 ^ (uint32_t)tmp_lane_100000dbd_2f_52_1;
                    RDX_10 = (uint64_t)(uint32_t)tmp_lane_100000dbd_37_55_1;
                    break;
                }
            case 0:
            default:
                break;
            }
            {
                uint32_t tmp_lane_100000dd4_2_59_1 = (uint32_t)RSI_0 ^ (uint32_t)RDX_10;
                uint32_t tmp_lane_100000dd4_e_5e_1 = tmp_lane_100000dd4_2_59_1 >> 16;
                int32_t tmp_lane_100000dd4_34_62_1 = (int32_t)(tmp_lane_100000dd4_e_5e_1 ^ tmp_lane_100000dd4_2_59_1);
                uint64_t tmp_4c780_13 = (uint64_t)tmp_lane_100000dd4_34_62_1 * 0xffffffff85ebca6bU;
                uint32_t tmp_lane_100000dd4_3f_65_1 = (uint32_t)tmp_4c780_13;
                uint32_t tmp_lane_100000dd4_49_69_1 = tmp_lane_100000dd4_3f_65_1 >> 13;
                int32_t tmp_lane_100000dd4_6f_6d_1 = (int32_t)(tmp_lane_100000dd4_49_69_1 ^ tmp_lane_100000dd4_3f_65_1);
                uint64_t tmp_4c780_14 = (uint64_t)tmp_lane_100000dd4_6f_6d_1 * 0xffffffffc2b2ae35U;
                uint32_t tmp_lane_100000dd4_7a_70_1 = (uint32_t)tmp_4c780_14;
                uint32_t tmp_lane_100000dd4_84_74_1 = tmp_lane_100000dd4_7a_70_1 >> 16;
                uint32_t tmp_lane_100000dd4_aa_78_1 = tmp_lane_100000dd4_84_74_1 ^ tmp_lane_100000dd4_7a_70_1;
                return tmp_lane_100000dd4_aa_78_1;
            }
        }
    }
}

