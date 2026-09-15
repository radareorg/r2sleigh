uint32_t sym__xxhash32(uint64_t RDI_0, uint64_t RSI_0, uint64_t RDX_0)
{
    /* r2dec proof: no individual construct is marked; 263 source obligations: 213 rendered, 50 elided, 0 refused; 136 statements rendered */
    {
        uint64_t RCX_6;
        uint64_t RAX_1 = RSI_0 + RDI_0;
        uint64_t tmp_3ea80_1 = RSI_0;
        uint8_t CF_1 = tmp_3ea80_1 < 16;
        if (CF_1) {
            uint32_t tmp_lane_100000985_0_3b_1 = (uint32_t)RDX_0;
            uint32_t tmp_lane_100000985_2_3c_1 = tmp_lane_100000985_0_3b_1 + 0x165667b1;
            RCX_6 = (uint64_t)(uint32_t)tmp_lane_100000985_2_3c_1;
        } else {
            uint64_t R10_1;
            uint64_t R9_1;
            uint64_t RCX_1;
            int32_t tmp_lane_100000910_54_12_1;
            uint32_t tmp_lane_100000910_91_1c_1;
            uint32_t tmp_lane_100000910_b8_24_1;
            uint32_t tmp_lane_100000910_c1_26_1;
            uint64_t R8_1 = RAX_1 - 16;
            R10_1 = (uint64_t)(uint32_t)(RDX_0 + 0x24234428);
            R9_1 = (uint64_t)(uint32_t)(RDX_0 - 0x7a143589);
            RCX_1 = (uint64_t)(uint32_t)(RDX_0 + 0x61c8864f);
            for (; ; ) {
                int32_t tmp_11f00_2 = (int32_t)*(uint32_t*)RDI_0;
                uint64_t tmp_4c780_2 = (uint64_t)tmp_11f00_2 * 0xffffffff85ebca77U;
                int32_t tmp_lane_100000910_4_3_1 = (int32_t)tmp_4c780_2;
                uint32_t tmp_lane_100000910_a_5_1 = (uint32_t)R10_1;
                uint32_t tmp_lane_100000910_c_6_1 = (uint32_t)tmp_lane_100000910_4_3_1 + tmp_lane_100000910_a_5_1;
                int32_t tmp_lane_100000910_18_9_1 = (int32_t)(tmp_lane_100000910_c_6_1 << 13 | tmp_lane_100000910_c_6_1 >> 19);
                int32_t tmp_11f00_3 = (int32_t)((uint32_t*)RDI_0)[1];
                uint64_t tmp_4c780_3 = (uint64_t)tmp_11f00_3 * 0xffffffff85ebca77U;
                int32_t tmp_lane_100000910_2d_a_1 = (int32_t)tmp_4c780_3;
                uint32_t tmp_lane_100000910_33_c_1 = (uint32_t)R9_1;
                uint32_t tmp_lane_100000910_35_d_1 = (uint32_t)tmp_lane_100000910_2d_a_1 + tmp_lane_100000910_33_c_1;
                int32_t tmp_lane_100000910_41_10_1 = (int32_t)(tmp_lane_100000910_35_d_1 << 13 | tmp_lane_100000910_35_d_1 >> 19);
                uint64_t tmp_4c780_4 = (uint64_t)tmp_lane_100000910_18_9_1 * 0xffffffff9e3779b1U;
                tmp_lane_100000910_54_12_1 = (int32_t)tmp_4c780_4;
                R10_1 = (uint64_t)(uint32_t)tmp_lane_100000910_54_12_1;
                int32_t tmp_11f00_4 = (int32_t)((uint32_t*)RDI_0)[2];
                uint64_t tmp_4c780_5 = (uint64_t)tmp_11f00_4 * 0xffffffff85ebca77U;
                int32_t tmp_lane_100000910_5f_13_1 = (int32_t)tmp_4c780_5;
                uint32_t tmp_lane_100000910_65_15_1 = (uint32_t)RDX_0;
                uint32_t tmp_lane_100000910_67_16_1 = (uint32_t)tmp_lane_100000910_5f_13_1 + tmp_lane_100000910_65_15_1;
                int32_t tmp_lane_100000910_73_19_1 = (int32_t)(tmp_lane_100000910_67_16_1 << 13 | tmp_lane_100000910_67_16_1 >> 19);
                int32_t tmp_11f00_5 = (int32_t)((uint32_t*)RDI_0)[3];
                uint64_t tmp_4c780_6 = (uint64_t)tmp_11f00_5 * 0xffffffff85ebca77U;
                int32_t tmp_lane_100000910_88_1a_1 = (int32_t)tmp_4c780_6;
                uint64_t tmp_4c780_7 = (uint64_t)tmp_lane_100000910_41_10_1 * 0xffffffff9e3779b1U;
                tmp_lane_100000910_91_1c_1 = (uint32_t)tmp_4c780_7;
                R9_1 = (uint64_t)(uint32_t)tmp_lane_100000910_91_1c_1;
                uint32_t tmp_lane_100000910_97_1e_1 = (uint32_t)RCX_1;
                uint32_t tmp_lane_100000910_99_1f_1 = (uint32_t)tmp_lane_100000910_88_1a_1 + tmp_lane_100000910_97_1e_1;
                int32_t tmp_lane_100000910_a5_22_1 = (int32_t)(tmp_lane_100000910_99_1f_1 << 13 | tmp_lane_100000910_99_1f_1 >> 19);
                uint64_t tmp_4c780_8 = (uint64_t)tmp_lane_100000910_73_19_1 * 0xffffffff9e3779b1U;
                tmp_lane_100000910_b8_24_1 = (uint32_t)tmp_4c780_8;
                RDX_0 = (uint64_t)(uint32_t)tmp_lane_100000910_b8_24_1;
                uint64_t tmp_4c780_9 = (uint64_t)tmp_lane_100000910_a5_22_1 * 0xffffffff9e3779b1U;
                tmp_lane_100000910_c1_26_1 = (uint32_t)tmp_4c780_9;
                RCX_1 = (uint64_t)(uint32_t)tmp_lane_100000910_c1_26_1;
                RDI_0 += 16;
                uint64_t tmp_3f080_2 = RDI_0;
                uint8_t CF_20 = tmp_3f080_2 < R8_1;
                uint8_t ZF_8 = tmp_3f080_2 == R8_1;
                if (!(CF_20 || ZF_8)) {
                    break;
                }
            }
            {
                uint8_t CF_21 = tmp_lane_100000910_54_12_1 < 0;
                uint32_t tmp_lane_10000096e_3_28_1 = (uint32_t)tmp_lane_100000910_54_12_1 << 1 | (uint32_t)CF_21;
                uint32_t tmp_lane_10000096e_b_2a_1 = tmp_lane_100000910_91_1c_1 << 7 | tmp_lane_100000910_91_1c_1 >> 25;
                uint32_t tmp_lane_10000096e_1d_2d_1 = tmp_lane_10000096e_b_2a_1 + tmp_lane_10000096e_3_28_1;
                uint32_t tmp_lane_10000096e_29_30_1 = tmp_lane_100000910_b8_24_1 << 12 | tmp_lane_100000910_b8_24_1 >> 20;
                uint32_t tmp_lane_10000096e_3d_32_1 = tmp_lane_100000910_c1_26_1 << 18 | tmp_lane_100000910_c1_26_1 >> 14;
                uint32_t tmp_lane_10000096e_4f_35_1 = tmp_lane_10000096e_3d_32_1 + tmp_lane_10000096e_29_30_1;
                uint32_t tmp_lane_10000096e_59_39_1 = tmp_lane_10000096e_4f_35_1 + tmp_lane_10000096e_1d_2d_1;
                RCX_6 = (uint64_t)(uint32_t)tmp_lane_10000096e_59_39_1;
            }
        }
        {
            uint64_t RSI_1;
            uint64_t RCX_10;
            uint64_t RDI_4;
            uint32_t tmp_lane_10000098d_0_40_1 = (uint32_t)RSI_0;
            uint32_t tmp_lane_10000098d_0_41_1 = (uint32_t)RCX_6;
            uint32_t tmp_lane_10000098d_2_42_1 = tmp_lane_10000098d_0_40_1 + tmp_lane_10000098d_0_41_1;
            RSI_1 = (uint64_t)(uint32_t)tmp_lane_10000098d_2_42_1;
            uint64_t RCX_9 = RDI_0 + 4;
            uint64_t tmp_3f080_4 = RCX_9;
            uint8_t CF_31 = tmp_3f080_4 < RAX_1;
            uint8_t ZF_15 = tmp_3f080_4 == RAX_1;
            RDI_4 = RDI_0;
            if (CF_31 || ZF_15) {
                for (; ; ) {
                    int32_t tmp_11f00_8 = (int32_t)*(uint32_t*)RDI_4;
                    uint64_t tmp_4c780_12 = (uint64_t)tmp_11f00_8 * 0xffffffffc2b2ae3dU;
                    int32_t tmp_lane_1000009a0_4_44_1 = (int32_t)tmp_4c780_12;
                    uint32_t tmp_lane_1000009a0_a_46_1 = (uint32_t)RSI_1;
                    uint32_t tmp_lane_1000009a0_c_47_1 = (uint32_t)tmp_lane_1000009a0_4_44_1 + tmp_lane_1000009a0_a_46_1;
                    int32_t tmp_lane_1000009a0_18_4a_1 = (int32_t)(tmp_lane_1000009a0_c_47_1 << 17 | tmp_lane_1000009a0_c_47_1 >> 15);
                    uint64_t tmp_4c780_13 = (uint64_t)tmp_lane_1000009a0_18_4a_1 * 0x27d4eb2f;
                    int32_t tmp_lane_1000009a0_2b_4c_1 = (int32_t)tmp_4c780_13;
                    RSI_1 = (uint64_t)(uint32_t)tmp_lane_1000009a0_2b_4c_1;
                    RCX_10 = RDI_4 + 4;
                    RDI_4 += 8;
                    uint64_t tmp_3f080_6 = RDI_4;
                    uint8_t CF_38 = tmp_3f080_6 < RAX_1;
                    uint8_t ZF_19 = tmp_3f080_6 == RAX_1;
                    uint64_t RDI_6 = RCX_10;
                    RDI_4 = RDI_6;
                    if (!(CF_38 || ZF_19)) {
                        break;
                    }
                }
                goto L3;
            } else {
                RCX_10 = RDI_0;
                goto L3;
            }
            for (; ; ) {
                uint64_t tmp_3f080_8;
L3: ;
                tmp_3f080_8 = RCX_10;
                uint8_t CF_40 = tmp_3f080_8 < RAX_1;
                if (CF_40) {
                    uint8_t tmp_11e00_2 = *(uint8_t*)RCX_10;
                    int32_t tmp_lane_1000009d0_1_4d_1 = (int32_t)tmp_11e00_2;
                    uint64_t tmp_4c780_15 = (uint64_t)tmp_lane_1000009d0_1_4d_1 * 0x165667b1;
                    int32_t tmp_lane_1000009d0_6_4f_1 = (int32_t)tmp_4c780_15;
                    uint32_t tmp_lane_1000009d0_c_51_1 = (uint32_t)RSI_1;
                    uint32_t tmp_lane_1000009d0_e_52_1 = (uint32_t)tmp_lane_1000009d0_6_4f_1 + tmp_lane_1000009d0_c_51_1;
                    int32_t tmp_lane_1000009d0_1a_55_1 = (int32_t)(tmp_lane_1000009d0_e_52_1 << 11 | tmp_lane_1000009d0_e_52_1 >> 21);
                    uint64_t tmp_4c780_16 = (uint64_t)tmp_lane_1000009d0_1a_55_1 * 0xffffffff9e3779b1U;
                    int32_t tmp_lane_1000009d0_2d_57_1 = (int32_t)tmp_4c780_16;
                    RSI_1 = (uint64_t)(uint32_t)tmp_lane_1000009d0_2d_57_1;
                    RCX_10++;
                } else {
                    break;
                }
            }
            {
                uint32_t tmp_lane_1000009ec_0_58_1 = (uint32_t)RSI_1;
                uint32_t tmp_lane_1000009ec_4_5b_1 = tmp_lane_1000009ec_0_58_1 >> 15;
                int32_t tmp_lane_1000009ec_2a_5f_1 = (int32_t)((uint32_t)RSI_1 ^ tmp_lane_1000009ec_4_5b_1);
                uint64_t tmp_4c780_17 = (uint64_t)tmp_lane_1000009ec_2a_5f_1 * 0xffffffff85ebca77U;
                uint32_t tmp_lane_1000009ec_35_62_1 = (uint32_t)tmp_4c780_17;
                uint32_t tmp_lane_1000009ec_3f_66_1 = tmp_lane_1000009ec_35_62_1 >> 13;
                int32_t tmp_lane_1000009ec_65_6a_1 = (int32_t)(tmp_lane_1000009ec_3f_66_1 ^ tmp_lane_1000009ec_35_62_1);
                uint64_t tmp_4c780_18 = (uint64_t)tmp_lane_1000009ec_65_6a_1 * 0xffffffffc2b2ae3dU;
                uint32_t tmp_lane_1000009ec_70_6d_1 = (uint32_t)tmp_4c780_18;
                uint32_t tmp_lane_1000009ec_7a_71_1 = tmp_lane_1000009ec_70_6d_1 >> 16;
                uint32_t tmp_lane_1000009ec_a0_75_1 = tmp_lane_1000009ec_7a_71_1 ^ tmp_lane_1000009ec_70_6d_1;
                return tmp_lane_1000009ec_a0_75_1;
            }
        }
    }
}

