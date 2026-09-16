uint32_t sym__xxhash32(uint64_t RDI_0, uint64_t RSI_0, uint64_t RDX_0)
{
    /* r2dec proof: no individual construct is marked; 376 source obligations: 314 rendered, 62 elided, 0 refused; 97 statements rendered */
    {
        uint64_t RCX_6;
        uint64_t RAX_1 = RSI_0 + RDI_0;
        if (RSI_0 < 16) {
            RCX_6 = (uint64_t)(uint32_t)((uint32_t)RDX_0 + 0x165667b1);
        } else {
            uint64_t R10_1;
            uint64_t R9_1;
            uint64_t RCX_1;
            int32_t tmp_lane_100000e40_54_12_1;
            uint32_t tmp_lane_100000e40_91_1c_1;
            uint32_t tmp_lane_100000e40_b8_24_1;
            uint32_t tmp_lane_100000e40_c1_26_1;
            uint64_t R8_1 = RAX_1 - 16;
            R10_1 = (uint64_t)(uint32_t)(RDX_0 + 0x24234428);
            R9_1 = (uint64_t)(uint32_t)(RDX_0 - 0x7a143589);
            RCX_1 = (uint64_t)(uint32_t)(RDX_0 + 0x61c8864f);
            for (; ; ) {
                int32_t tmp_11f00_2 = (int32_t)*(uint32_t*)RDI_0;
                uint32_t tmp_lane_100000e40_c_6_1 = (uint32_t)((uint64_t)tmp_11f00_2 * 0xffffffff85ebca77U) + (uint32_t)R10_1;
                int32_t tmp_11f00_3 = (int32_t)((uint32_t*)RDI_0)[1];
                uint32_t tmp_lane_100000e40_35_d_1 = (uint32_t)((uint64_t)tmp_11f00_3 * 0xffffffff85ebca77U) + (uint32_t)R9_1;
                tmp_lane_100000e40_54_12_1 = (int32_t)((uint64_t)(int32_t)(tmp_lane_100000e40_c_6_1 << 13 | tmp_lane_100000e40_c_6_1 >> 19) * 0xffffffff9e3779b1U);
                R10_1 = (uint64_t)(uint32_t)tmp_lane_100000e40_54_12_1;
                int32_t tmp_11f00_4 = (int32_t)((uint32_t*)RDI_0)[2];
                uint32_t tmp_lane_100000e40_67_16_1 = (uint32_t)((uint64_t)tmp_11f00_4 * 0xffffffff85ebca77U) + (uint32_t)RDX_0;
                int32_t tmp_11f00_5 = (int32_t)((uint32_t*)RDI_0)[3];
                tmp_lane_100000e40_91_1c_1 = (uint32_t)((uint64_t)(int32_t)(tmp_lane_100000e40_35_d_1 << 13 | tmp_lane_100000e40_35_d_1 >> 19) * 0xffffffff9e3779b1U);
                R9_1 = (uint64_t)(uint32_t)tmp_lane_100000e40_91_1c_1;
                uint32_t tmp_lane_100000e40_99_1f_1 = (uint32_t)((uint64_t)tmp_11f00_5 * 0xffffffff85ebca77U) + (uint32_t)RCX_1;
                tmp_lane_100000e40_b8_24_1 = (uint32_t)((uint64_t)(int32_t)(tmp_lane_100000e40_67_16_1 << 13 | tmp_lane_100000e40_67_16_1 >> 19) * 0xffffffff9e3779b1U);
                RDX_0 = (uint64_t)(uint32_t)tmp_lane_100000e40_b8_24_1;
                tmp_lane_100000e40_c1_26_1 = (uint32_t)((uint64_t)(int32_t)(tmp_lane_100000e40_99_1f_1 << 13 | tmp_lane_100000e40_99_1f_1 >> 19) * 0xffffffff9e3779b1U);
                RCX_1 = (uint64_t)(uint32_t)tmp_lane_100000e40_c1_26_1;
                RDI_0 += 16;
                uint64_t tmp_3f080_2 = RDI_0;
                if (R8_1 < tmp_3f080_2) {
                    break;
                }
            }
            RCX_6 = (uint64_t)(uint32_t)((tmp_lane_100000e40_c1_26_1 << 18 | tmp_lane_100000e40_c1_26_1 >> 14) + (((uint32_t)tmp_lane_100000e40_54_12_1 << 1 | (uint32_t)(tmp_lane_100000e40_54_12_1 < 0)) + (tmp_lane_100000e40_91_1c_1 << 7 | tmp_lane_100000e40_91_1c_1 >> 25) + (tmp_lane_100000e40_b8_24_1 << 12 | tmp_lane_100000e40_b8_24_1 >> 20)));
        }
        {
            uint64_t RSI_1;
            uint64_t RCX_10;
            uint64_t RDI_4;
            RSI_1 = (uint64_t)(uint32_t)((uint32_t)RSI_0 + (uint32_t)RCX_6);
            uint64_t tmp_3f080_4 = RDI_0 + 4;
            RDI_4 = RDI_0;
            if (tmp_3f080_4 <= RAX_1) {
                for (; ; ) {
                    int32_t tmp_11f00_8 = (int32_t)*(uint32_t*)RDI_4;
                    uint32_t tmp_lane_100000ed0_c_47_1 = (uint32_t)((uint64_t)tmp_11f00_8 * 0xffffffffc2b2ae3dU) + (uint32_t)RSI_1;
                    RSI_1 = (uint64_t)(uint32_t)((uint64_t)(int32_t)(tmp_lane_100000ed0_c_47_1 << 17 | tmp_lane_100000ed0_c_47_1 >> 15) * 0x27d4eb2f);
                    uint64_t RCX_15 = RDI_4 + 4;
                    uint64_t tmp_3f080_6 = RDI_4 + 8;
                    uint64_t RDI_6 = RCX_15;
                    RDI_4 = RDI_6;
                    RCX_10 = RCX_15;
                    if (RAX_1 < tmp_3f080_6) {
                        break;
                    }
                }
            } else {
                RCX_10 = RDI_0;
            }
            {
                uint64_t RSI_22;
                uint64_t RDX_6 = RCX_10;
                uint64_t RDX_7 = RDX_6 - RAX_1;
                RSI_22 = RSI_1;
                if (RDX_6 < RAX_1) {
                    uint64_t RDI_11;
                    uint32_t tmp_lane_100000efd_e_54_1 = (uint32_t)RAX_1 - (uint32_t)RCX_10 & 3;
                    uint64_t RDI_10 = (uint64_t)(uint32_t)tmp_lane_100000efd_e_54_1;
                    RDI_11 = RDI_10;
                    if (tmp_lane_100000efd_e_54_1 != 0) {
                        for (; ; ) {
                            uint8_t tmp_11e00_2 = *(uint8_t*)RCX_10;
                            uint32_t tmp_lane_100000f10_e_5b_1 = (uint32_t)((uint64_t)(int32_t)tmp_11e00_2 * 0x165667b1) + (uint32_t)RSI_1;
                            RSI_1 = (uint64_t)(uint32_t)((uint64_t)(int32_t)(tmp_lane_100000f10_e_5b_1 << 11 | tmp_lane_100000f10_e_5b_1 >> 21) * 0xffffffff9e3779b1U);
                            RCX_10++;
                            uint64_t RDI_12 = RDI_11 - 1;
                            uint8_t tmp_12800_2 = RDI_11 != 1;
                            RDI_11 = RDI_12;
                            if (!tmp_12800_2) {
                                break;
                            }
                        }
                    }
                    {
                        uint64_t tmp_3ea80_2 = RDX_7;
                        RSI_22 = RSI_1;
                        if ((uint64_t)-0x4 >= tmp_3ea80_2) {
                            for (; ; ) {
                                uint8_t tmp_11e00_5 = *(uint8_t*)RCX_10;
                                uint32_t tmp_lane_100000f40_e_66_1 = (uint32_t)((uint64_t)(int32_t)tmp_11e00_5 * 0x165667b1) + (uint32_t)RSI_1;
                                uint8_t tmp_11e00_6 = ((uint8_t*)RCX_10)[1];
                                uint32_t tmp_lane_100000f40_42_71_1 = (uint32_t)((uint64_t)(int32_t)tmp_11e00_6 * 0x165667b1) + (uint32_t)((uint64_t)(int32_t)(tmp_lane_100000f40_e_66_1 << 11 | tmp_lane_100000f40_e_66_1 >> 21) * 0xffffffff9e3779b1U);
                                uint8_t tmp_11e00_7 = ((uint8_t*)RCX_10)[2];
                                uint32_t tmp_lane_100000f40_76_7c_1 = (uint32_t)((uint64_t)(int32_t)tmp_11e00_7 * 0x165667b1) + (uint32_t)((uint64_t)(int32_t)(tmp_lane_100000f40_42_71_1 << 11 | tmp_lane_100000f40_42_71_1 >> 21) * 0xffffffff9e3779b1U);
                                uint8_t tmp_11e00_8 = ((uint8_t*)RCX_10)[3];
                                uint32_t tmp_lane_100000f40_aa_87_1 = (uint32_t)((uint64_t)(int32_t)tmp_11e00_8 * 0x165667b1) + (uint32_t)((uint64_t)(int32_t)(tmp_lane_100000f40_76_7c_1 << 11 | tmp_lane_100000f40_76_7c_1 >> 21) * 0xffffffff9e3779b1U);
                                RSI_1 = (uint64_t)(uint32_t)((uint64_t)(int32_t)(tmp_lane_100000f40_aa_87_1 << 11 | tmp_lane_100000f40_aa_87_1 >> 21) * 0xffffffff9e3779b1U);
                                RCX_10 += 4;
                                uint8_t CF_68 = RCX_10 < RAX_1;
                                RSI_22 = RSI_1;
                                if (!CF_68) {
                                    break;
                                }
                            }
                        }
                    }
                }
                {
                    uint32_t tmp_lane_100000f9c_35_97_1 = (uint32_t)((uint64_t)(int32_t)((uint32_t)RSI_22 >> 15 ^ (uint32_t)RSI_22) * 0xffffffff85ebca77U);
                    uint32_t tmp_lane_100000f9c_70_a2_1 = (uint32_t)((uint64_t)(int32_t)(tmp_lane_100000f9c_35_97_1 >> 13 ^ tmp_lane_100000f9c_35_97_1) * 0xffffffffc2b2ae3dU);
                    return tmp_lane_100000f9c_70_a2_1 >> 16 ^ tmp_lane_100000f9c_70_a2_1;
                }
            }
        }
    }
}

