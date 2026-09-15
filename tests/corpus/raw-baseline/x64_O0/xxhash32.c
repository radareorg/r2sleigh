uint32_t sym__xxhash32(uint64_t RDI_0, uint64_t RSI_0, uint32_t EDX_0)
{
    uint32_t sym__rotl32(uint32_t, uint8_t);

    /* r2dec proof: no individual construct is marked; 565 source obligations: 380 rendered, 185 elided, 0 refused; 196 statements rendered */
    {
        uint32_t stack_m44;
        uint64_t stack_m40;
        int32_t stack_m28;
        uint64_t stack_m24;
        uint64_t stack_m16;
        uint64_t tmp_11f80_1;
        uint64_t tmp_11f80_6;
        stack_m16 = RDI_0;
        stack_m24 = RSI_0;
        stack_m28 = (int32_t)EDX_0;
        tmp_11f80_1 = stack_m16;
        uint64_t RAX_2 = tmp_11f80_1 + stack_m24;
        stack_m40 = RAX_2;
        {
            int32_t tmp_11f00_1;
            if (stack_m24 < 16) {
                tmp_11f00_1 = (int32_t)stack_m28;
                uint32_t tmp_lane_100000cc7_6_60_1 = (uint32_t)tmp_11f00_1 + 0x165667b1;
                stack_m44 = tmp_lane_100000cc7_6_60_1;
            } else {
                int32_t stack_m72;
                int32_t stack_m68;
                int32_t stack_m64;
                int32_t stack_m60;
                uint64_t stack_m56;
                tmp_11f80_6 = stack_m40;
                uint64_t RAX_4 = tmp_11f80_6 - 16;
                stack_m56 = RAX_4;
                tmp_11f00_1 = (int32_t)stack_m28;
                uint32_t tmp_lane_100000b5a_15_3_1 = (uint32_t)tmp_11f00_1 - 0x61c8864f;
                int32_t tmp_lane_100000b5a_1f_6_1 = (int32_t)(tmp_lane_100000b5a_15_3_1 - 0x7a143589);
                stack_m60 = tmp_lane_100000b5a_1f_6_1;
                tmp_11f00_1 = (int32_t)stack_m28;
                int32_t tmp_lane_100000b5a_30_b_1 = (int32_t)((uint32_t)tmp_11f00_1 - 0x7a143589);
                stack_m64 = tmp_lane_100000b5a_30_b_1;
                tmp_11f00_1 = (int32_t)stack_m28;
                stack_m68 = tmp_11f00_1;
                tmp_11f00_1 = (int32_t)stack_m28;
                int32_t tmp_lane_100000b5a_48_12_1 = (int32_t)((uint32_t)tmp_11f00_1 + 0x61c8864f);
                stack_m72 = tmp_lane_100000b5a_48_12_1;
                for (; ; ) {
                    int32_t stack_m76;
                    tmp_11f80_1 = stack_m16;
                    int32_t tmp_11f00_6 = (int32_t)*(uint32_t*)tmp_11f80_1;
                    stack_m76 = tmp_11f00_6;
                    uint64_t tmp_4c780_2 = (uint64_t)stack_m76 * 0xffffffff85ebca77U;
                    int32_t tmp_lane_100000b92_12_18_1 = (int32_t)tmp_4c780_2;
                    uint32_t tmp_lane_100000b92_1a_1b_1 = (uint32_t)stack_m60 + (uint32_t)tmp_lane_100000b92_12_18_1;
                    uint64_t RAX_17 = (uint64_t)sym__rotl32((uint32_t)tmp_lane_100000b92_1a_1b_1, 13);
                    uint64_t tmp_4c780_3 = (uint64_t)(int32_t)RAX_17 * 0xffffffff9e3779b1U;
                    int32_t tmp_lane_100000b92_29_1e_1 = (int32_t)tmp_4c780_3;
                    stack_m60 = tmp_lane_100000b92_29_1e_1;
                    tmp_11f80_1 = stack_m16;
                    uint64_t RAX_20 = tmp_11f80_1 + 4;
                    stack_m16 = RAX_20;
                    tmp_11f80_1 = stack_m16;
                    int32_t tmp_11f00_9 = (int32_t)*(uint32_t*)tmp_11f80_1;
                    stack_m76 = tmp_11f00_9;
                    uint64_t tmp_4c780_4 = (uint64_t)stack_m76 * 0xffffffff85ebca77U;
                    int32_t tmp_lane_100000b92_53_23_1 = (int32_t)tmp_4c780_4;
                    uint32_t tmp_lane_100000b92_5b_26_1 = (uint32_t)stack_m64 + (uint32_t)tmp_lane_100000b92_53_23_1;
                    uint64_t RAX_24 = (uint64_t)sym__rotl32((uint32_t)tmp_lane_100000b92_5b_26_1, 13);
                    uint64_t tmp_4c780_5 = (uint64_t)(int32_t)RAX_24 * 0xffffffff9e3779b1U;
                    int32_t tmp_lane_100000b92_6a_29_1 = (int32_t)tmp_4c780_5;
                    stack_m64 = tmp_lane_100000b92_6a_29_1;
                    tmp_11f80_1 = stack_m16;
                    uint64_t RAX_27 = tmp_11f80_1 + 4;
                    stack_m16 = RAX_27;
                    tmp_11f80_1 = stack_m16;
                    int32_t tmp_11f00_12 = (int32_t)*(uint32_t*)tmp_11f80_1;
                    stack_m76 = tmp_11f00_12;
                    uint64_t tmp_4c780_6 = (uint64_t)stack_m76 * 0xffffffff85ebca77U;
                    int32_t tmp_lane_100000b92_94_2e_1 = (int32_t)tmp_4c780_6;
                    uint32_t tmp_lane_100000b92_9c_31_1 = (uint32_t)stack_m68 + (uint32_t)tmp_lane_100000b92_94_2e_1;
                    uint64_t RAX_31 = (uint64_t)sym__rotl32((uint32_t)tmp_lane_100000b92_9c_31_1, 13);
                    uint64_t tmp_4c780_7 = (uint64_t)(int32_t)RAX_31 * 0xffffffff9e3779b1U;
                    int32_t tmp_lane_100000b92_ab_34_1 = (int32_t)tmp_4c780_7;
                    stack_m68 = tmp_lane_100000b92_ab_34_1;
                    tmp_11f80_1 = stack_m16;
                    uint64_t RAX_34 = tmp_11f80_1 + 4;
                    stack_m16 = RAX_34;
                    tmp_11f80_1 = stack_m16;
                    int32_t tmp_11f00_15 = (int32_t)*(uint32_t*)tmp_11f80_1;
                    stack_m76 = tmp_11f00_15;
                    uint64_t tmp_4c780_8 = (uint64_t)stack_m76 * 0xffffffff85ebca77U;
                    int32_t tmp_lane_100000b92_d5_39_1 = (int32_t)tmp_4c780_8;
                    uint32_t tmp_lane_100000b92_dd_3c_1 = (uint32_t)stack_m72 + (uint32_t)tmp_lane_100000b92_d5_39_1;
                    uint64_t RAX_38 = (uint64_t)sym__rotl32((uint32_t)tmp_lane_100000b92_dd_3c_1, 13);
                    uint64_t tmp_4c780_9 = (uint64_t)(int32_t)RAX_38 * 0xffffffff9e3779b1U;
                    int32_t tmp_lane_100000b92_ec_3f_1 = (int32_t)tmp_4c780_9;
                    stack_m72 = tmp_lane_100000b92_ec_3f_1;
                    tmp_11f80_1 = stack_m16;
                    uint64_t RAX_41 = tmp_11f80_1 + 4;
                    stack_m16 = RAX_41;
                    tmp_11f80_1 = stack_m16;
                    uint64_t tmp_3f800_2 = stack_m56;
                    uint8_t tmp_12900_2 = tmp_11f80_1 <= tmp_3f800_2;
                    if (!tmp_12900_2) {
                        break;
                    }
                }
                {
                    uint32_t stack_m92;
                    uint32_t stack_m88;
                    int32_t stack_m84;
                    uint64_t RAX_43 = (uint64_t)sym__rotl32((uint32_t)stack_m60, 1);
                    stack_m92 = (uint32_t)RAX_43;
                    uint64_t RAX_44 = (uint64_t)sym__rotl32((uint32_t)stack_m64, 7);
                    uint32_t tmp_lane_100000c70_13_44_1 = (uint32_t)RAX_44;
                    uint32_t tmp_lane_100000c70_1b_49_1 = stack_m92 + tmp_lane_100000c70_13_44_1;
                    stack_m88 = tmp_lane_100000c70_1b_49_1;
                    uint64_t RAX_47 = (uint64_t)sym__rotl32((uint32_t)stack_m68, 12);
                    uint32_t tmp_lane_100000c70_2e_4d_1 = (uint32_t)RAX_47;
                    int32_t tmp_lane_100000c70_36_52_1 = (int32_t)(stack_m88 + tmp_lane_100000c70_2e_4d_1);
                    stack_m84 = tmp_lane_100000c70_36_52_1;
                    uint64_t RDI_13 = (uint64_t)(uint32_t)stack_m72;
                    uint64_t RAX_50 = (uint64_t)sym__rotl32((uint32_t)RDI_13, 18);
                    uint32_t tmp_lane_100000c70_49_56_1 = (uint32_t)RAX_50;
                    uint32_t tmp_lane_100000c70_51_5b_1 = (uint32_t)stack_m84 + tmp_lane_100000c70_49_56_1;
                    stack_m44 = tmp_lane_100000c70_51_5b_1;
                }
            }
        }
        {
            uint32_t tmp_11f00_27;
            tmp_11f00_27 = stack_m44;
            uint32_t tmp_lane_100000cd2_5_63_1 = (uint32_t)stack_m24;
            tmp_11f00_27 = stack_m44;
            tmp_11f00_27 = stack_m44;
            uint32_t tmp_lane_100000cd2_9_64_1 = tmp_lane_100000cd2_5_63_1 + tmp_11f00_27;
            stack_m44 = tmp_lane_100000cd2_9_64_1;
            for (; ; ) {
                tmp_11f80_1 = stack_m16;
                uint64_t RAX_60 = tmp_11f80_1 + 4;
                tmp_11f80_6 = stack_m40;
                uint64_t tmp_3f800_5 = tmp_11f80_6;
                uint8_t tmp_12a80_2 = tmp_3f800_5 < RAX_60;
                if (tmp_12a80_2) {
                    break;
                } else {
                    uint32_t stack_m80;
                    uint64_t RAX_67;
                    tmp_11f80_1 = stack_m16;
                    uint32_t tmp_11f00_31 = *(uint32_t*)tmp_11f80_1;
                    stack_m80 = tmp_11f00_31;
                    tmp_11f00_27 = stack_m44;
                    uint64_t tmp_4c780_12 = (uint64_t)(int32_t)stack_m80 * 0xffffffffc2b2ae3dU;
                    int32_t tmp_lane_100000cea_12_6a_1 = (int32_t)tmp_4c780_12;
                    uint32_t tmp_lane_100000cea_1a_6d_1 = tmp_11f00_27 + (uint32_t)tmp_lane_100000cea_12_6a_1;
                    uint64_t RDI_17 = (uint64_t)(uint32_t)tmp_lane_100000cea_1a_6d_1;
                    uint64_t RAX_64 = (uint64_t)sym__rotl32((uint32_t)RDI_17, 17);
                    uint64_t tmp_4c780_13 = (uint64_t)(int32_t)RAX_64 * 0x27d4eb2f;
                    uint32_t tmp_lane_100000cea_29_70_1 = (uint32_t)tmp_4c780_13;
                    stack_m44 = tmp_lane_100000cea_29_70_1;
                    tmp_11f80_1 = stack_m16;
                    RAX_67 = tmp_11f80_1;
                    RAX_67 += 4;
                    stack_m16 = RAX_67;
                }
            }
            {
                for (; ; ) {
                    tmp_11f80_1 = stack_m16;
                    uint64_t RAX_69 = tmp_11f80_1;
                    tmp_11f80_6 = stack_m40;
                    uint64_t tmp_3f800_7 = tmp_11f80_6;
                    uint8_t CF_41 = RAX_69 < tmp_3f800_7;
                    if (!CF_41) {
                        break;
                    } else {
                        uint64_t RAX_76;
                        tmp_11f00_27 = stack_m44;
                        tmp_11f80_1 = stack_m16;
                        uint8_t tmp_11e00_2 = *(uint8_t*)tmp_11f80_1;
                        uint64_t tmp_4c780_15 = (uint64_t)(int32_t)tmp_11e00_2 * 0x165667b1;
                        int32_t tmp_lane_100000d2c_d_75_1 = (int32_t)tmp_4c780_15;
                        uint32_t tmp_lane_100000d2c_15_78_1 = tmp_11f00_27 + (uint32_t)tmp_lane_100000d2c_d_75_1;
                        uint64_t RAX_73 = (uint64_t)sym__rotl32((uint32_t)tmp_lane_100000d2c_15_78_1, 11);
                        uint64_t tmp_4c780_16 = (uint64_t)(int32_t)RAX_73 * 0xffffffff9e3779b1U;
                        uint32_t tmp_lane_100000d2c_24_7b_1 = (uint32_t)tmp_4c780_16;
                        stack_m44 = tmp_lane_100000d2c_24_7b_1;
                        tmp_11f80_1 = stack_m16;
                        RAX_76 = tmp_11f80_1;
                        RAX_76++;
                        stack_m16 = RAX_76;
                    }
                }
                {
                    tmp_11f00_27 = stack_m44;
                    uint32_t tmp_lane_100000d5f_6_7f_1 = tmp_11f00_27 >> 15;
                    tmp_11f00_27 = stack_m44;
                    uint32_t tmp_lane_100000d5f_2e_82_1 = tmp_lane_100000d5f_6_7f_1 ^ tmp_11f00_27;
                    stack_m44 = tmp_lane_100000d5f_2e_82_1;
                    tmp_11f00_27 = stack_m44;
                    uint64_t tmp_4c780_17 = (uint64_t)(int32_t)tmp_11f00_27 * 0xffffffff85ebca77U;
                    uint32_t tmp_lane_100000d5f_3e_85_1 = (uint32_t)tmp_4c780_17;
                    stack_m44 = tmp_lane_100000d5f_3e_85_1;
                    tmp_11f00_27 = stack_m44;
                    uint32_t tmp_lane_100000d5f_4d_89_1 = tmp_11f00_27 >> 13;
                    tmp_11f00_27 = stack_m44;
                    uint32_t tmp_lane_100000d5f_75_8c_1 = tmp_lane_100000d5f_4d_89_1 ^ tmp_11f00_27;
                    stack_m44 = tmp_lane_100000d5f_75_8c_1;
                    tmp_11f00_27 = stack_m44;
                    uint64_t tmp_4c780_18 = (uint64_t)(int32_t)tmp_11f00_27 * 0xffffffffc2b2ae3dU;
                    uint32_t tmp_lane_100000d5f_85_8f_1 = (uint32_t)tmp_4c780_18;
                    stack_m44 = tmp_lane_100000d5f_85_8f_1;
                    tmp_11f00_27 = stack_m44;
                    uint32_t tmp_lane_100000d5f_94_93_1 = tmp_11f00_27 >> 16;
                    tmp_11f00_27 = stack_m44;
                    uint32_t tmp_lane_100000d5f_bc_96_1 = tmp_lane_100000d5f_94_93_1 ^ tmp_11f00_27;
                    stack_m44 = tmp_lane_100000d5f_bc_96_1;
                    tmp_11f00_27 = stack_m44;
                    return tmp_11f00_27;
                }
            }
        }
    }
}

