uint32_t sym__xxhash32(uint64_t X0_0, uint64_t X1_0, uint32_t W2_0)
{
    uint32_t sym__rotl32(uint32_t, uint8_t);

    /* r2dec proof: no individual construct is marked; 383 source obligations: 304 rendered, 79 elided, 0 refused; 90 statements rendered */
    {
        uint32_t stack_m36;
        uint64_t stack_m32;
        uint64_t stack_m24;
        uint64_t X8_5;
        uint64_t X9_1;
        uint32_t stack_m52;
        stack_m24 = X0_0;
        stack_m32 = X1_0;
        stack_m36 = W2_0;
        X8_5 = stack_m24;
        X9_1 = stack_m32;
        uint64_t tmp_3b180_3 = X8_5 + X9_1;
        X9_1 = stack_m32;
        {
            uint32_t tmp_24d00_1;
            if (X9_1 < 16) {
                tmp_24d00_1 = stack_m36;
                stack_m52 = tmp_24d00_1 + 0x165667b1;
            } else {
                uint32_t stack_m68;
                uint32_t stack_m72;
                uint32_t stack_m80;
                uint64_t stack_m64 = tmp_3b180_3 - 16;
                tmp_24d00_1 = stack_m36;
                stack_m68 = tmp_24d00_1 + 0x24234428;
                tmp_24d00_1 = stack_m36;
                stack_m72 = tmp_24d00_1 - 0x7a143589;
                tmp_24d00_1 = stack_m36;
                tmp_24d00_1 = stack_m36;
                stack_m80 = tmp_24d00_1 + 0x61c8864f;
                for (; ; ) {
                    X8_5 = stack_m24;
                    uint32_t tmp_24c00_5 = *(uint32_t*)X8_5;
                    uint32_t X0_3 = sym__rotl32((uint32_t)(stack_m68 - tmp_24c00_5 * 0x7a143589), 13);
                    stack_m68 = (uint32_t)X0_3 * 0x9e3779b1;
                    X8_5 = stack_m24;
                    stack_m24 = X8_5 + 4;
                    X8_5 = stack_m24;
                    uint32_t tmp_24c00_11 = *(uint32_t*)X8_5;
                    uint32_t X0_5 = sym__rotl32((uint32_t)(stack_m72 - tmp_24c00_11 * 0x7a143589), 13);
                    stack_m72 = (uint32_t)X0_5 * 0x9e3779b1;
                    X8_5 = stack_m24;
                    stack_m24 = X8_5 + 4;
                    X8_5 = stack_m24;
                    uint32_t tmp_24c00_17 = *(uint32_t*)X8_5;
                    uint32_t X0_7 = sym__rotl32((uint32_t)(tmp_24d00_1 - tmp_24c00_17 * 0x7a143589), 13);
                    tmp_24d00_1 = (uint32_t)X0_7 * 0x9e3779b1;
                    X8_5 = stack_m24;
                    stack_m24 = X8_5 + 4;
                    X8_5 = stack_m24;
                    uint32_t tmp_24c00_23 = *(uint32_t*)X8_5;
                    uint32_t X0_9 = sym__rotl32((uint32_t)(stack_m80 - tmp_24c00_23 * 0x7a143589), 13);
                    stack_m80 = (uint32_t)X0_9 * 0x9e3779b1;
                    X8_5 = stack_m24;
                    stack_m24 = X8_5 + 4;
                    {
                        X8_5 = stack_m24;
                        uint64_t tmp_3e680_2 = stack_m64;
                        if (tmp_3e680_2 < X8_5) {
                            break;
                        }
                    }
                }
                {
                    uint32_t X0_11 = sym__rotl32((uint32_t)stack_m68, 1);
                    uint32_t X0_13 = sym__rotl32((uint32_t)stack_m72, 7);
                    uint32_t X0_16 = sym__rotl32((uint32_t)tmp_24d00_1, 12);
                    uint32_t X0_18 = sym__rotl32((uint32_t)stack_m80, 18);
                    stack_m52 = (uint32_t)X0_11 + (uint32_t)X0_13 + (uint32_t)X0_16 + (uint32_t)X0_18;
                }
            }
        }
        {
            uint32_t stack_m52_2;
            X9_1 = stack_m32;
            stack_m52_2 = stack_m52 + (uint32_t)X9_1;
            for (; ; ) {
                X8_5 = stack_m24;
                uint64_t tmp_11f80_9 = X8_5 + 4;
                uint64_t tmp_3e680_5 = tmp_3b180_3;
                if (tmp_3e680_5 < tmp_11f80_9) {
                    break;
                } else {
                    X8_5 = stack_m24;
                    uint32_t tmp_24c00_36 = *(uint32_t*)X8_5;
                    uint32_t X0_22 = sym__rotl32((uint32_t)(stack_m52_2 - tmp_24c00_36 * 0x3d4d51c3), 17);
                    stack_m52_2 = (uint32_t)X0_22 * 0x27d4eb2f;
                    X8_5 = stack_m24;
                    stack_m24 = X8_5 + 4;
                }
            }
            {
                for (; ; ) {
                    X8_5 = stack_m24;
                    if (tmp_3b180_3 <= X8_5) {
                        break;
                    } else {
                        X8_5 = stack_m24;
                        uint8_t tmp_25500_2 = *(uint8_t*)X8_5;
                        uint32_t X0_25 = sym__rotl32((uint32_t)(stack_m52_2 + (uint32_t)tmp_25500_2 * 0x165667b1), 11);
                        stack_m52_2 = (uint32_t)X0_25 * 0x9e3779b1;
                        X8_5 = stack_m24;
                        stack_m24 = X8_5 + 1;
                    }
                }
                {
                    uint32_t tmp_2b380_17 = (stack_m52_2 >> 15 ^ stack_m52_2) * 0x85ebca77;
                    uint32_t tmp_2b380_18 = (tmp_2b380_17 >> 13 ^ tmp_2b380_17) * 0xc2b2ae3d;
                    return tmp_2b380_18 >> 16 ^ tmp_2b380_18;
                }
            }
        }
    }
}

