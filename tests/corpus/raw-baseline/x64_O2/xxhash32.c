uint32_t sym__xxhash32(uint64_t RDI_0, uint64_t RSI_0, uint64_t RDX_0)
{
    /* r2dec proof: no individual construct is marked; 376 source obligations: 314 rendered, 62 elided, 0 refused; 195 statements rendered */
    {
        uint64_t RCX_6;
        uint64_t RAX_1 = RSI_0 + RDI_0;
        uint64_t tmp_3ea80_1 = RSI_0;
        uint8_t CF_1 = tmp_3ea80_1 < 16;
        if (CF_1) {
            uint32_t tmp_lane_100000eb5_0_3b_1 = (uint32_t)RDX_0;
            uint32_t tmp_lane_100000eb5_2_3c_1 = tmp_lane_100000eb5_0_3b_1 + 0x165667b1;
            RCX_6 = (uint64_t)(uint32_t)tmp_lane_100000eb5_2_3c_1;
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
                uint64_t tmp_4c780_2 = (uint64_t)tmp_11f00_2 * 0xffffffff85ebca77U;
                int32_t tmp_lane_100000e40_4_3_1 = (int32_t)tmp_4c780_2;
                uint32_t tmp_lane_100000e40_a_5_1 = (uint32_t)R10_1;
                uint32_t tmp_lane_100000e40_c_6_1 = (uint32_t)tmp_lane_100000e40_4_3_1 + tmp_lane_100000e40_a_5_1;
                int32_t tmp_lane_100000e40_18_9_1 = (int32_t)(tmp_lane_100000e40_c_6_1 << 13 | tmp_lane_100000e40_c_6_1 >> 19);
                int32_t tmp_11f00_3 = (int32_t)((uint32_t*)RDI_0)[1];
                uint64_t tmp_4c780_3 = (uint64_t)tmp_11f00_3 * 0xffffffff85ebca77U;
                int32_t tmp_lane_100000e40_2d_a_1 = (int32_t)tmp_4c780_3;
                uint32_t tmp_lane_100000e40_33_c_1 = (uint32_t)R9_1;
                uint32_t tmp_lane_100000e40_35_d_1 = (uint32_t)tmp_lane_100000e40_2d_a_1 + tmp_lane_100000e40_33_c_1;
                int32_t tmp_lane_100000e40_41_10_1 = (int32_t)(tmp_lane_100000e40_35_d_1 << 13 | tmp_lane_100000e40_35_d_1 >> 19);
                uint64_t tmp_4c780_4 = (uint64_t)tmp_lane_100000e40_18_9_1 * 0xffffffff9e3779b1U;
                tmp_lane_100000e40_54_12_1 = (int32_t)tmp_4c780_4;
                R10_1 = (uint64_t)(uint32_t)tmp_lane_100000e40_54_12_1;
                int32_t tmp_11f00_4 = (int32_t)((uint32_t*)RDI_0)[2];
                uint64_t tmp_4c780_5 = (uint64_t)tmp_11f00_4 * 0xffffffff85ebca77U;
                int32_t tmp_lane_100000e40_5f_13_1 = (int32_t)tmp_4c780_5;
                uint32_t tmp_lane_100000e40_65_15_1 = (uint32_t)RDX_0;
                uint32_t tmp_lane_100000e40_67_16_1 = (uint32_t)tmp_lane_100000e40_5f_13_1 + tmp_lane_100000e40_65_15_1;
                int32_t tmp_lane_100000e40_73_19_1 = (int32_t)(tmp_lane_100000e40_67_16_1 << 13 | tmp_lane_100000e40_67_16_1 >> 19);
                int32_t tmp_11f00_5 = (int32_t)((uint32_t*)RDI_0)[3];
                uint64_t tmp_4c780_6 = (uint64_t)tmp_11f00_5 * 0xffffffff85ebca77U;
                int32_t tmp_lane_100000e40_88_1a_1 = (int32_t)tmp_4c780_6;
                uint64_t tmp_4c780_7 = (uint64_t)tmp_lane_100000e40_41_10_1 * 0xffffffff9e3779b1U;
                tmp_lane_100000e40_91_1c_1 = (uint32_t)tmp_4c780_7;
                R9_1 = (uint64_t)(uint32_t)tmp_lane_100000e40_91_1c_1;
                uint32_t tmp_lane_100000e40_97_1e_1 = (uint32_t)RCX_1;
                uint32_t tmp_lane_100000e40_99_1f_1 = (uint32_t)tmp_lane_100000e40_88_1a_1 + tmp_lane_100000e40_97_1e_1;
                int32_t tmp_lane_100000e40_a5_22_1 = (int32_t)(tmp_lane_100000e40_99_1f_1 << 13 | tmp_lane_100000e40_99_1f_1 >> 19);
                uint64_t tmp_4c780_8 = (uint64_t)tmp_lane_100000e40_73_19_1 * 0xffffffff9e3779b1U;
                tmp_lane_100000e40_b8_24_1 = (uint32_t)tmp_4c780_8;
                RDX_0 = (uint64_t)(uint32_t)tmp_lane_100000e40_b8_24_1;
                uint64_t tmp_4c780_9 = (uint64_t)tmp_lane_100000e40_a5_22_1 * 0xffffffff9e3779b1U;
                tmp_lane_100000e40_c1_26_1 = (uint32_t)tmp_4c780_9;
                RCX_1 = (uint64_t)(uint32_t)tmp_lane_100000e40_c1_26_1;
                RDI_0 += 16;
                uint64_t tmp_3f080_2 = RDI_0;
                uint8_t CF_20 = tmp_3f080_2 < R8_1;
                uint8_t ZF_8 = tmp_3f080_2 == R8_1;
                if (!(CF_20 || ZF_8)) {
                    break;
                }
            }
            {
                uint8_t CF_21 = tmp_lane_100000e40_54_12_1 < 0;
                uint32_t tmp_lane_100000e9e_3_28_1 = (uint32_t)tmp_lane_100000e40_54_12_1 << 1 | (uint32_t)CF_21;
                uint32_t tmp_lane_100000e9e_b_2a_1 = tmp_lane_100000e40_91_1c_1 << 7 | tmp_lane_100000e40_91_1c_1 >> 25;
                uint32_t tmp_lane_100000e9e_1d_2d_1 = tmp_lane_100000e9e_b_2a_1 + tmp_lane_100000e9e_3_28_1;
                uint32_t tmp_lane_100000e9e_29_30_1 = tmp_lane_100000e40_b8_24_1 << 12 | tmp_lane_100000e40_b8_24_1 >> 20;
                uint32_t tmp_lane_100000e9e_3d_32_1 = tmp_lane_100000e40_c1_26_1 << 18 | tmp_lane_100000e40_c1_26_1 >> 14;
                uint32_t tmp_lane_100000e9e_4f_35_1 = tmp_lane_100000e9e_3d_32_1 + tmp_lane_100000e9e_29_30_1;
                uint32_t tmp_lane_100000e9e_59_39_1 = tmp_lane_100000e9e_4f_35_1 + tmp_lane_100000e9e_1d_2d_1;
                RCX_6 = (uint64_t)(uint32_t)tmp_lane_100000e9e_59_39_1;
            }
        }
        {
            uint64_t RSI_1;
            uint64_t RCX_10;
            uint64_t RDI_4;
            uint32_t tmp_lane_100000ebd_0_40_1 = (uint32_t)RSI_0;
            uint32_t tmp_lane_100000ebd_0_41_1 = (uint32_t)RCX_6;
            uint32_t tmp_lane_100000ebd_2_42_1 = tmp_lane_100000ebd_0_40_1 + tmp_lane_100000ebd_0_41_1;
            RSI_1 = (uint64_t)(uint32_t)tmp_lane_100000ebd_2_42_1;
            uint64_t RCX_9 = RDI_0 + 4;
            uint64_t tmp_3f080_4 = RCX_9;
            uint8_t CF_31 = tmp_3f080_4 < RAX_1;
            uint8_t ZF_15 = tmp_3f080_4 == RAX_1;
            RDI_4 = RDI_0;
            if (CF_31 || ZF_15) {
                for (; ; ) {
                    int32_t tmp_11f00_8 = (int32_t)*(uint32_t*)RDI_4;
                    uint64_t tmp_4c780_12 = (uint64_t)tmp_11f00_8 * 0xffffffffc2b2ae3dU;
                    int32_t tmp_lane_100000ed0_4_44_1 = (int32_t)tmp_4c780_12;
                    uint32_t tmp_lane_100000ed0_a_46_1 = (uint32_t)RSI_1;
                    uint32_t tmp_lane_100000ed0_c_47_1 = (uint32_t)tmp_lane_100000ed0_4_44_1 + tmp_lane_100000ed0_a_46_1;
                    int32_t tmp_lane_100000ed0_18_4a_1 = (int32_t)(tmp_lane_100000ed0_c_47_1 << 17 | tmp_lane_100000ed0_c_47_1 >> 15);
                    uint64_t tmp_4c780_13 = (uint64_t)tmp_lane_100000ed0_18_4a_1 * 0x27d4eb2f;
                    int32_t tmp_lane_100000ed0_2b_4c_1 = (int32_t)tmp_4c780_13;
                    RSI_1 = (uint64_t)(uint32_t)tmp_lane_100000ed0_2b_4c_1;
                    uint64_t RCX_15 = RDI_4 + 4;
                    RDI_4 += 8;
                    uint64_t tmp_3f080_6 = RDI_4;
                    uint8_t CF_38 = tmp_3f080_6 < RAX_1;
                    uint8_t ZF_19 = tmp_3f080_6 == RAX_1;
                    uint64_t RDI_6 = RCX_15;
                    RDI_4 = RDI_6;
                    RCX_10 = RCX_15;
                    if (!(CF_38 || ZF_19)) {
                        break;
                    }
                }
            } else {
                RCX_10 = RDI_0;
            }
            {
                uint64_t RSI_22;
                uint64_t RDX_6 = RCX_10;
                uint8_t CF_40 = RDX_6 < RAX_1;
                uint64_t RDX_7 = RDX_6 - RAX_1;
                RSI_22 = RSI_1;
                if (CF_40) {
                    uint64_t RDI_11;
                    uint32_t tmp_lane_100000efd_0_4d_1 = (uint32_t)RAX_1;
                    uint32_t tmp_lane_100000efd_2_50_1 = (uint32_t)RCX_10;
                    uint32_t tmp_lane_100000efd_4_51_1 = tmp_lane_100000efd_0_4d_1 - tmp_lane_100000efd_2_50_1;
                    uint32_t tmp_lane_100000efd_e_54_1 = tmp_lane_100000efd_4_51_1 & 3;
                    uint64_t RDI_10 = (uint64_t)(uint32_t)tmp_lane_100000efd_e_54_1;
                    uint8_t ZF_23 = tmp_lane_100000efd_e_54_1 == 0;
                    RDI_11 = RDI_10;
                    if (!ZF_23) {
                        for (; ; ) {
                            uint8_t tmp_11e00_2 = *(uint8_t*)RCX_10;
                            int32_t tmp_lane_100000f10_1_56_1 = (int32_t)tmp_11e00_2;
                            uint64_t tmp_4c780_16 = (uint64_t)tmp_lane_100000f10_1_56_1 * 0x165667b1;
                            int32_t tmp_lane_100000f10_6_58_1 = (int32_t)tmp_4c780_16;
                            uint32_t tmp_lane_100000f10_c_5a_1 = (uint32_t)RSI_1;
                            uint32_t tmp_lane_100000f10_e_5b_1 = (uint32_t)tmp_lane_100000f10_6_58_1 + tmp_lane_100000f10_c_5a_1;
                            int32_t tmp_lane_100000f10_1a_5e_1 = (int32_t)(tmp_lane_100000f10_e_5b_1 << 11 | tmp_lane_100000f10_e_5b_1 >> 21);
                            uint64_t tmp_4c780_17 = (uint64_t)tmp_lane_100000f10_1a_5e_1 * 0xffffffff9e3779b1U;
                            int32_t tmp_lane_100000f10_2d_60_1 = (int32_t)tmp_4c780_17;
                            RSI_1 = (uint64_t)(uint32_t)tmp_lane_100000f10_2d_60_1;
                            RCX_10++;
                            uint64_t RDI_12 = RDI_11 - 1;
                            uint8_t ZF_27 = RDI_11 == 1;
                            RDI_11 = RDI_12;
                            if (ZF_27) {
                                break;
                            }
                        }
                    }
                    {
                        uint64_t tmp_3ea80_2 = RDX_7;
                        uint8_t CF_49 = tmp_3ea80_2 < (uint64_t)-0x4;
                        uint8_t ZF_29 = tmp_3ea80_2 == (uint64_t)-0x4;
                        RSI_22 = RSI_1;
                        if (CF_49 || ZF_29) {
                            for (; ; ) {
                                uint8_t tmp_11e00_5 = *(uint8_t*)RCX_10;
                                int32_t tmp_lane_100000f40_1_61_1 = (int32_t)tmp_11e00_5;
                                uint64_t tmp_4c780_20 = (uint64_t)tmp_lane_100000f40_1_61_1 * 0x165667b1;
                                int32_t tmp_lane_100000f40_6_63_1 = (int32_t)tmp_4c780_20;
                                uint32_t tmp_lane_100000f40_c_65_1 = (uint32_t)RSI_1;
                                uint32_t tmp_lane_100000f40_e_66_1 = (uint32_t)tmp_lane_100000f40_6_63_1 + tmp_lane_100000f40_c_65_1;
                                int32_t tmp_lane_100000f40_1a_69_1 = (int32_t)(tmp_lane_100000f40_e_66_1 << 11 | tmp_lane_100000f40_e_66_1 >> 21);
                                uint64_t tmp_4c780_21 = (uint64_t)tmp_lane_100000f40_1a_69_1 * 0xffffffff9e3779b1U;
                                int32_t tmp_lane_100000f40_2d_6b_1 = (int32_t)tmp_4c780_21;
                                uint8_t tmp_11e00_6 = ((uint8_t*)RCX_10)[1];
                                int32_t tmp_lane_100000f40_35_6c_1 = (int32_t)tmp_11e00_6;
                                uint64_t tmp_4c780_22 = (uint64_t)tmp_lane_100000f40_35_6c_1 * 0x165667b1;
                                int32_t tmp_lane_100000f40_3a_6e_1 = (int32_t)tmp_4c780_22;
                                uint32_t tmp_lane_100000f40_42_71_1 = (uint32_t)tmp_lane_100000f40_3a_6e_1 + (uint32_t)tmp_lane_100000f40_2d_6b_1;
                                int32_t tmp_lane_100000f40_4e_74_1 = (int32_t)(tmp_lane_100000f40_42_71_1 << 11 | tmp_lane_100000f40_42_71_1 >> 21);
                                uint64_t tmp_4c780_23 = (uint64_t)tmp_lane_100000f40_4e_74_1 * 0xffffffff9e3779b1U;
                                int32_t tmp_lane_100000f40_61_76_1 = (int32_t)tmp_4c780_23;
                                uint8_t tmp_11e00_7 = ((uint8_t*)RCX_10)[2];
                                int32_t tmp_lane_100000f40_69_77_1 = (int32_t)tmp_11e00_7;
                                uint64_t tmp_4c780_24 = (uint64_t)tmp_lane_100000f40_69_77_1 * 0x165667b1;
                                int32_t tmp_lane_100000f40_6e_79_1 = (int32_t)tmp_4c780_24;
                                uint32_t tmp_lane_100000f40_76_7c_1 = (uint32_t)tmp_lane_100000f40_6e_79_1 + (uint32_t)tmp_lane_100000f40_61_76_1;
                                int32_t tmp_lane_100000f40_82_7f_1 = (int32_t)(tmp_lane_100000f40_76_7c_1 << 11 | tmp_lane_100000f40_76_7c_1 >> 21);
                                uint64_t tmp_4c780_25 = (uint64_t)tmp_lane_100000f40_82_7f_1 * 0xffffffff9e3779b1U;
                                int32_t tmp_lane_100000f40_95_81_1 = (int32_t)tmp_4c780_25;
                                uint8_t tmp_11e00_8 = ((uint8_t*)RCX_10)[3];
                                int32_t tmp_lane_100000f40_9d_82_1 = (int32_t)tmp_11e00_8;
                                uint64_t tmp_4c780_26 = (uint64_t)tmp_lane_100000f40_9d_82_1 * 0x165667b1;
                                int32_t tmp_lane_100000f40_a2_84_1 = (int32_t)tmp_4c780_26;
                                uint32_t tmp_lane_100000f40_aa_87_1 = (uint32_t)tmp_lane_100000f40_a2_84_1 + (uint32_t)tmp_lane_100000f40_95_81_1;
                                int32_t tmp_lane_100000f40_b6_8a_1 = (int32_t)(tmp_lane_100000f40_aa_87_1 << 11 | tmp_lane_100000f40_aa_87_1 >> 21);
                                uint64_t tmp_4c780_27 = (uint64_t)tmp_lane_100000f40_b6_8a_1 * 0xffffffff9e3779b1U;
                                int32_t tmp_lane_100000f40_c9_8c_1 = (int32_t)tmp_4c780_27;
                                RSI_1 = (uint64_t)(uint32_t)tmp_lane_100000f40_c9_8c_1;
                                RCX_10 += 4;
                                uint64_t tmp_3f080_9 = RCX_10;
                                uint8_t CF_68 = tmp_3f080_9 < RAX_1;
                                RSI_22 = RSI_1;
                                if (!CF_68) {
                                    break;
                                }
                            }
                        }
                    }
                }
                {
                    uint32_t tmp_lane_100000f9c_0_8d_1 = (uint32_t)RSI_22;
                    uint32_t tmp_lane_100000f9c_4_90_1 = tmp_lane_100000f9c_0_8d_1 >> 15;
                    int32_t tmp_lane_100000f9c_2a_94_1 = (int32_t)((uint32_t)RSI_22 ^ tmp_lane_100000f9c_4_90_1);
                    uint64_t tmp_4c780_29 = (uint64_t)tmp_lane_100000f9c_2a_94_1 * 0xffffffff85ebca77U;
                    uint32_t tmp_lane_100000f9c_35_97_1 = (uint32_t)tmp_4c780_29;
                    uint32_t tmp_lane_100000f9c_3f_9b_1 = tmp_lane_100000f9c_35_97_1 >> 13;
                    int32_t tmp_lane_100000f9c_65_9f_1 = (int32_t)(tmp_lane_100000f9c_3f_9b_1 ^ tmp_lane_100000f9c_35_97_1);
                    uint64_t tmp_4c780_30 = (uint64_t)tmp_lane_100000f9c_65_9f_1 * 0xffffffffc2b2ae3dU;
                    uint32_t tmp_lane_100000f9c_70_a2_1 = (uint32_t)tmp_4c780_30;
                    uint32_t tmp_lane_100000f9c_7a_a6_1 = tmp_lane_100000f9c_70_a2_1 >> 16;
                    uint32_t tmp_lane_100000f9c_a0_aa_1 = tmp_lane_100000f9c_7a_a6_1 ^ tmp_lane_100000f9c_70_a2_1;
                    return tmp_lane_100000f9c_a0_aa_1;
                }
            }
        }
    }
}

