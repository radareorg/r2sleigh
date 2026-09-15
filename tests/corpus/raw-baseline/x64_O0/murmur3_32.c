uint32_t sym__murmur3_32(uint64_t RDI_0, uint64_t RSI_0, uint32_t EDX_0)
{
    uint32_t sym__rotl32(uint32_t, uint8_t);

    /* r2dec proof: no individual construct is marked; 379 source obligations: 254 rendered, 125 elided, 0 refused; 142 statements rendered */
    {
        uint64_t stack_m56;
        uint64_t stack_m48;
        uint32_t stack_m32;
        uint32_t stack_m28;
        uint64_t stack_m24;
        uint64_t stack_m16;
        uint64_t tmp_11f80_1;
        uint32_t tmp_11f00_10;
        stack_m16 = RDI_0;
        stack_m24 = RSI_0;
        stack_m28 = EDX_0;
        uint32_t tmp_11f00_1 = stack_m28;
        stack_m32 = tmp_11f00_1;
        tmp_11f80_1 = stack_m24;
        tmp_11f80_1 >>= 2;
        stack_m48 = tmp_11f80_1;
        stack_m56 = 0;
        for (; ; ) {
            uint64_t RAX_5 = stack_m56;
            uint64_t tmp_3f800_2 = stack_m48;
            uint8_t CF_4 = RAX_5 < tmp_3f800_2;
            if (!CF_4) {
                break;
            } else {
                int32_t stack_m60;
                uint64_t RAX_17;
                uint64_t RCX_2;
                int32_t tmp_11f00_4;
                RCX_2 = stack_m56;
                RCX_2 <<= 2;
                int32_t tmp_11f00_3 = (int32_t)*(uint32_t*)(stack_m16 + RCX_2);
                stack_m60 = tmp_11f00_3;
                tmp_11f00_4 = (int32_t)stack_m60;
                uint64_t tmp_4c780_2 = (uint64_t)tmp_11f00_4 * 0xffffffffcc9e2d51U;
                int32_t tmp_lane_1000009a5_38_5_1 = (int32_t)tmp_4c780_2;
                stack_m60 = tmp_lane_1000009a5_38_5_1;
                tmp_11f00_4 = (int32_t)stack_m60;
                uint64_t RAX_9 = (uint64_t)sym__rotl32((uint32_t)tmp_11f00_4, 15);
                stack_m60 = (int32_t)RAX_9;
                tmp_11f00_4 = (int32_t)stack_m60;
                uint64_t tmp_4c780_3 = (uint64_t)tmp_11f00_4 * 0x1b873593;
                int32_t tmp_lane_1000009a5_51_9_1 = (int32_t)tmp_4c780_3;
                stack_m60 = tmp_lane_1000009a5_51_9_1;
                tmp_11f00_4 = (int32_t)stack_m60;
                tmp_11f00_10 = stack_m32;
                uint32_t tmp_lane_1000009a5_62_d_1 = (uint32_t)tmp_11f00_4 ^ tmp_11f00_10;
                stack_m32 = tmp_lane_1000009a5_62_d_1;
                tmp_11f00_10 = stack_m32;
                uint64_t RDI_3 = (uint64_t)(uint32_t)tmp_11f00_10;
                uint64_t RAX_13 = (uint64_t)sym__rotl32((uint32_t)RDI_3, 13);
                stack_m32 = (uint32_t)RAX_13;
                tmp_11f00_10 = stack_m32;
                uint64_t tmp_4bd00_2 = (uint64_t)(int32_t)tmp_11f00_10 * 5;
                int32_t tmp_lane_1000009a5_7d_12_1 = (int32_t)tmp_4bd00_2;
                uint32_t tmp_lane_1000009a5_85_14_1 = (uint32_t)tmp_lane_1000009a5_7d_12_1 - 0x19ab949c;
                stack_m32 = tmp_lane_1000009a5_85_14_1;
                RAX_17 = stack_m56;
                RAX_17++;
                stack_m56 = RAX_17;
            }
        }
        {
            uint64_t stack_m88;
            uint32_t stack_m76;
            uint64_t stack_m72;
            uint64_t tmp_11f80_13;
            uint32_t tmp_11f00_11;
            stack_m72 = stack_m16 + stack_m48 * 4;
            stack_m76 = 0;
            tmp_11f80_1 = stack_m24;
            uint32_t tmp_lane_100000a0e_14_18_1 = (uint32_t)tmp_11f80_1 & 3;
            uint64_t RAX_21 = (uint64_t)(uint32_t)tmp_lane_100000a0e_14_18_1;
            stack_m88 = RAX_21;
            uint8_t ZF_10 = RAX_21 == 1;
            if (!ZF_10) {
                uint8_t ZF_11 = stack_m88 == 2;
                if (!ZF_11) {
                    uint8_t ZF_12 = stack_m88 == 3;
                    if (!ZF_12) {
                        goto L3;
                    } else {
                        tmp_11f80_13 = stack_m72;
                        uint8_t tmp_11e00_1 = *(uint8_t*)(tmp_11f80_13 + 2);
                        uint32_t tmp_lane_100000a50_5_1a_1 = (uint32_t)tmp_11e00_1;
                        uint32_t tmp_lane_100000a50_9_1c_1 = tmp_lane_100000a50_5_1a_1 << 16;
                        tmp_11f00_11 = stack_m76;
                        uint32_t tmp_lane_100000a50_31_1f_1 = tmp_lane_100000a50_9_1c_1 ^ tmp_11f00_11;
                        stack_m76 = tmp_lane_100000a50_31_1f_1;
                    }
                }
                {
                    tmp_11f80_13 = stack_m72;
                    uint8_t tmp_11e00_3 = *(uint8_t*)(tmp_11f80_13 + 1);
                    uint32_t tmp_lane_100000a61_5_22_1 = (uint32_t)tmp_11e00_3;
                    uint32_t tmp_lane_100000a61_9_24_1 = tmp_lane_100000a61_5_22_1 << 8;
                    tmp_11f00_11 = stack_m76;
                    uint32_t tmp_lane_100000a61_31_27_1 = tmp_lane_100000a61_9_24_1 ^ tmp_11f00_11;
                    stack_m76 = tmp_lane_100000a61_31_27_1;
                }
            }
            {
                tmp_11f80_13 = stack_m72;
                uint8_t tmp_11e00_5 = *(uint8_t*)tmp_11f80_13;
                uint32_t tmp_lane_100000a72_4_2a_1 = (uint32_t)tmp_11e00_5;
                tmp_11f00_11 = stack_m76;
                uint32_t tmp_lane_100000a72_a_2c_1 = tmp_lane_100000a72_4_2a_1 ^ tmp_11f00_11;
                stack_m76 = tmp_lane_100000a72_a_2c_1;
                tmp_11f00_11 = stack_m76;
                uint64_t tmp_4c780_4 = (uint64_t)(int32_t)tmp_11f00_11 * 0xffffffffcc9e2d51U;
                uint32_t tmp_lane_100000a72_1a_2f_1 = (uint32_t)tmp_4c780_4;
                stack_m76 = tmp_lane_100000a72_1a_2f_1;
                tmp_11f00_11 = stack_m76;
                uint64_t RDI_4 = (uint64_t)(uint32_t)tmp_11f00_11;
                uint64_t RAX_41 = (uint64_t)sym__rotl32((uint32_t)RDI_4, 15);
                stack_m76 = (uint32_t)RAX_41;
                tmp_11f00_11 = stack_m76;
                uint64_t tmp_4c780_5 = (uint64_t)(int32_t)tmp_11f00_11 * 0x1b873593;
                uint32_t tmp_lane_100000a72_33_33_1 = (uint32_t)tmp_4c780_5;
                stack_m76 = tmp_lane_100000a72_33_33_1;
                tmp_11f00_11 = stack_m76;
                tmp_11f00_10 = stack_m32;
                uint32_t tmp_lane_100000a72_44_37_1 = tmp_11f00_11 ^ tmp_11f00_10;
                stack_m32 = tmp_lane_100000a72_44_37_1;
            }
            {
L3: ;
                tmp_11f80_1 = stack_m24;
                tmp_11f00_10 = stack_m32;
                uint32_t tmp_lane_100000aac_7_3b_1 = (uint32_t)tmp_11f80_1 ^ tmp_11f00_10;
                stack_m32 = tmp_lane_100000aac_7_3b_1;
                tmp_11f00_10 = stack_m32;
                uint32_t tmp_lane_100000aac_18_40_1 = tmp_11f00_10 >> 16;
                tmp_11f00_10 = stack_m32;
                uint32_t tmp_lane_100000aac_40_43_1 = tmp_lane_100000aac_18_40_1 ^ tmp_11f00_10;
                stack_m32 = tmp_lane_100000aac_40_43_1;
                tmp_11f00_10 = stack_m32;
                uint64_t tmp_4c780_7 = (uint64_t)(int32_t)tmp_11f00_10 * 0xffffffff85ebca6bU;
                uint32_t tmp_lane_100000aac_50_46_1 = (uint32_t)tmp_4c780_7;
                stack_m32 = tmp_lane_100000aac_50_46_1;
                tmp_11f00_10 = stack_m32;
                uint32_t tmp_lane_100000aac_5f_4a_1 = tmp_11f00_10 >> 13;
                tmp_11f00_10 = stack_m32;
                uint32_t tmp_lane_100000aac_87_4d_1 = tmp_lane_100000aac_5f_4a_1 ^ tmp_11f00_10;
                stack_m32 = tmp_lane_100000aac_87_4d_1;
                tmp_11f00_10 = stack_m32;
                uint64_t tmp_4c780_8 = (uint64_t)(int32_t)tmp_11f00_10 * 0xffffffffc2b2ae35U;
                uint32_t tmp_lane_100000aac_97_50_1 = (uint32_t)tmp_4c780_8;
                stack_m32 = tmp_lane_100000aac_97_50_1;
                tmp_11f00_10 = stack_m32;
                uint32_t tmp_lane_100000aac_a6_54_1 = tmp_11f00_10 >> 16;
                tmp_11f00_10 = stack_m32;
                uint32_t tmp_lane_100000aac_ce_57_1 = tmp_lane_100000aac_a6_54_1 ^ tmp_11f00_10;
                stack_m32 = tmp_lane_100000aac_ce_57_1;
                tmp_11f00_10 = stack_m32;
                return tmp_11f00_10;
            }
        }
    }
}

