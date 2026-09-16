uint32_t sym__xxhash32(uint64_t X0_0, uint64_t X1_0, uint32_t W2_0)
{
    uint32_t sym__rotl32(uint32_t, uint8_t);

    /* r2dec proof: no individual construct is marked; 502 source obligations: 393 rendered, 109 elided, 0 refused; 148 statements rendered */
    {
        uint32_t stack_m52;
        uint64_t stack_m48;
        uint32_t stack_m36;
        uint64_t stack_m32;
        uint64_t stack_m24;
        uint64_t X8_5;
        uint64_t X9_1;
        uint32_t stack_m96 = 0x9e3779b1;
        uint32_t stack_m92 = 0x85ebca77;
        stack_m24 = X0_0;
        stack_m32 = X1_0;
        stack_m36 = W2_0;
        X8_5 = stack_m24;
        X9_1 = stack_m32;
        stack_m48 = X9_1 + X8_5;
        X9_1 = stack_m32;
        uint8_t TMPCY_3 = 16 <= X9_1;
        uint8_t CY_1 = TMPCY_3;
        uint8_t tmp_b00_1 = !CY_1;
        {
            uint32_t tmp_24d00_1;
            if (tmp_b00_1) {
                tmp_24d00_1 = stack_m36;
                uint32_t tmp_2a000_8 = 0x165667b1;
                uint32_t tmp_12180_13 = tmp_2a000_8;
                uint32_t tmp_12280_13 = tmp_24d00_1 + tmp_12180_13;
                stack_m52 = tmp_12280_13;
            } else {
                uint32_t stack_m68;
                uint32_t stack_m72;
                uint32_t stack_m80;
                uint32_t tmp_24c00_1 = stack_m92;
                uint32_t tmp_24c00_2 = stack_m96;
                uint64_t tmp_3e280_2 = stack_m48 - 16;
                uint64_t stack_m64 = tmp_3e280_2;
                tmp_24d00_1 = stack_m36;
                uint32_t tmp_12280_1 = tmp_24c00_2 + tmp_24d00_1;
                stack_m68 = tmp_24c00_1 + tmp_12280_1;
                tmp_24d00_1 = stack_m36;
                stack_m72 = tmp_24c00_1 + tmp_24d00_1;
                tmp_24d00_1 = stack_m36;
                tmp_24d00_1 = stack_m36;
                uint32_t tmp_2a000_6 = 0x61c8864f;
                uint32_t tmp_12180_4 = tmp_2a000_6;
                uint32_t tmp_12280_4 = tmp_24d00_1 + tmp_12180_4;
                stack_m80 = tmp_12280_4;
                for (; ; ) {
                    X8_5 = stack_m24;
                    uint32_t tmp_24c00_5 = *(uint32_t*)X8_5;
                    uint32_t tmp_24c00_6 = stack_m68;
                    uint64_t X0_3 = (uint64_t)sym__rotl32((uint32_t)(tmp_24c00_6 + stack_m92 * tmp_24c00_5), 13);
                    uint64_t X1_4 = (uint64_t)13;
                    stack_m68 = stack_m96 * (uint32_t)X0_3;
                    X8_5 = stack_m24;
                    stack_m24 = X8_5 + 4;
                    X8_5 = stack_m24;
                    uint32_t tmp_24c00_11 = *(uint32_t*)X8_5;
                    uint32_t tmp_24c00_12 = stack_m72;
                    uint64_t X0_5 = (uint64_t)sym__rotl32((uint32_t)(tmp_24c00_12 + stack_m92 * tmp_24c00_11), (uint8_t)X1_4);
                    uint64_t X1_6 = (uint64_t)13;
                    stack_m72 = stack_m96 * (uint32_t)X0_5;
                    X8_5 = stack_m24;
                    stack_m24 = X8_5 + 4;
                    X8_5 = stack_m24;
                    uint32_t tmp_24c00_17 = *(uint32_t*)X8_5;
                    uint32_t tmp_24c00_18 = tmp_24d00_1;
                    uint64_t X0_7 = (uint64_t)sym__rotl32((uint32_t)(tmp_24c00_18 + stack_m92 * tmp_24c00_17), (uint8_t)X1_6);
                    uint64_t X1_8 = (uint64_t)13;
                    tmp_24d00_1 = stack_m96 * (uint32_t)X0_7;
                    X8_5 = stack_m24;
                    stack_m24 = X8_5 + 4;
                    X8_5 = stack_m24;
                    uint32_t tmp_24c00_23 = *(uint32_t*)X8_5;
                    uint32_t tmp_24c00_24 = stack_m80;
                    uint64_t X0_9 = (uint64_t)sym__rotl32((uint32_t)(tmp_24c00_24 + stack_m92 * tmp_24c00_23), (uint8_t)X1_8);
                    stack_m80 = stack_m96 * (uint32_t)X0_9;
                    X8_5 = stack_m24;
                    stack_m24 = X8_5 + 4;
                    {
                        X8_5 = stack_m24;
                        uint64_t tmp_3e680_2 = stack_m64;
                        uint8_t TMPCY_18 = tmp_3e680_2 <= X8_5;
                        uint8_t TMPZR_18 = X8_5 == tmp_3e680_2;
                        uint8_t ZR_4 = TMPZR_18;
                        uint8_t CY_4 = TMPCY_18;
                        uint8_t tmp_1000_2 = !CY_4 || ZR_4;
                        if (!tmp_1000_2) {
                            break;
                        }
                    }
                }
                {
                    uint64_t X0_11 = (uint64_t)sym__rotl32((uint32_t)stack_m68, 1);
                    uint64_t X0_13 = (uint64_t)sym__rotl32((uint32_t)stack_m72, 7);
                    uint64_t X8_56 = X0_13;
                    uint32_t tmp_12280_10 = (uint32_t)X0_11 + (uint32_t)X8_56;
                    uint64_t X0_16 = (uint64_t)sym__rotl32((uint32_t)tmp_24d00_1, 12);
                    uint32_t tmp_12280_11 = tmp_12280_10 + (uint32_t)X0_16;
                    uint64_t X0_18 = (uint64_t)sym__rotl32((uint32_t)stack_m80, 18);
                    uint32_t tmp_24c00_33 = tmp_12280_11;
                    uint32_t tmp_12180_12 = (uint32_t)X0_18;
                    uint32_t tmp_12280_12 = tmp_24c00_33 + tmp_12180_12;
                    stack_m52 = tmp_12280_12;
                }
            }
        }
        {
            X9_1 = stack_m32;
            uint64_t X9_26 = X9_1;
            uint32_t tmp_24d00_7 = stack_m52;
            uint32_t tmp_12180_15 = (uint32_t)X9_26;
            uint32_t tmp_12280_15 = tmp_24d00_7 + tmp_12180_15;
            stack_m52 = tmp_12280_15;
            for (; ; ) {
                X8_5 = stack_m24;
                uint64_t X8_72 = X8_5 + 4;
                uint64_t tmp_3e680_5 = stack_m48;
                uint8_t TMPCY_27 = tmp_3e680_5 <= X8_72;
                uint8_t TMPZR_27 = X8_72 == tmp_3e680_5;
                uint8_t tmp_e80_2 = TMPCY_27 && !TMPZR_27;
                if (tmp_e80_2) {
                    break;
                } else {
                    X8_5 = stack_m24;
                    uint32_t tmp_24c00_36 = *(uint32_t*)X8_5;
                    uint32_t tmp_24d00_9 = stack_m52;
                    uint64_t X0_22 = (uint64_t)sym__rotl32((uint32_t)(tmp_24d00_9 - tmp_24c00_36 * 0x3d4d51c3), 17);
                    stack_m52 = (uint32_t)X0_22 * 0x27d4eb2f;
                    X8_5 = stack_m24;
                    uint64_t tmp_11f80_10 = X8_5 + 4;
                    stack_m24 = tmp_11f80_10;
                }
            }
            {
                for (; ; ) {
                    X8_5 = stack_m24;
                    uint64_t tmp_3e680_7 = stack_m48;
                    uint8_t TMPCY_31 = tmp_3e680_7 <= X8_5;
                    if (TMPCY_31) {
                        break;
                    } else {
                        uint32_t tmp_24d00_11 = stack_m52;
                        X8_5 = stack_m24;
                        uint8_t tmp_25500_2 = *(uint8_t*)X8_5;
                        uint64_t X0_25 = (uint64_t)sym__rotl32((uint32_t)(tmp_24d00_11 + (uint32_t)tmp_25500_2 * 0x165667b1), 11);
                        stack_m52 = stack_m96 * (uint32_t)X0_25;
                        X8_5 = stack_m24;
                        uint64_t tmp_11f80_12 = X8_5 + 1;
                        stack_m24 = tmp_11f80_12;
                    }
                }
                {
                    uint32_t tmp_24d00_12 = stack_m52;
                    uint32_t tmp_24d00_13 = stack_m52;
                    stack_m52 = tmp_24d00_12 >> 15 ^ tmp_24d00_13;
                    uint32_t tmp_24d00_14 = stack_m52;
                    stack_m52 = stack_m92 * tmp_24d00_14;
                    uint32_t tmp_24d00_15 = stack_m52;
                    uint32_t tmp_24d00_16 = stack_m52;
                    stack_m52 = tmp_24d00_15 >> 13 ^ tmp_24d00_16;
                    uint32_t tmp_24d00_17 = stack_m52;
                    stack_m52 = tmp_24d00_17 * 0xc2b2ae3d;
                    uint32_t tmp_24d00_18 = stack_m52;
                    uint32_t tmp_24d00_19 = stack_m52;
                    stack_m52 = tmp_24d00_18 >> 16 ^ tmp_24d00_19;
                    uint32_t tmp_24d00_20 = stack_m52;
                    return tmp_24d00_20;
                }
            }
        }
    }
}

