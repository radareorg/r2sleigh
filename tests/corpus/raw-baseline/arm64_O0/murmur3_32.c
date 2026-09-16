uint32_t sym__murmur3_32(uint64_t X0_0, uint64_t X1_0, uint32_t W2_0)
{
    uint32_t sym__rotl32(uint32_t, uint8_t);

    /* r2dec proof: no individual construct is marked; 314 source obligations: 229 rendered, 85 elided, 0 refused; 95 statements rendered */
    {
        uint64_t stack_m56;
        uint32_t stack_m40;
        uint32_t stack_m36;
        uint64_t stack_m32;
        uint64_t stack_m24;
        uint64_t X8_3;
        uint64_t stack_m64;
        uint32_t tmp_2a000_2 = 0xcc9e2d51;
        uint32_t stack_m92 = tmp_2a000_2;
        uint32_t tmp_2a000_4 = 0x1b873593;
        uint32_t stack_m88 = tmp_2a000_4;
        stack_m24 = X0_0;
        stack_m32 = X1_0;
        stack_m36 = W2_0;
        uint32_t tmp_24d00_1 = stack_m36;
        stack_m40 = tmp_24d00_1;
        X8_3 = stack_m32;
        uint64_t tmp_42488_1 = X8_3 / 4;
        stack_m56 = 0 ? 0 : tmp_42488_1;
        stack_m64 = 0;
        for (; ; ) {
            uint64_t X8_6 = stack_m64;
            uint64_t tmp_3e680_2 = stack_m56;
            uint8_t TMPCY_3 = tmp_3e680_2 <= X8_6;
            if (TMPCY_3) {
                break;
            } else {
                uint32_t tmp_25180_2 = ((uint32_t*)stack_m24)[stack_m64];
                uint32_t tmp_2b380_2 = stack_m92 * tmp_25180_2;
                uint64_t X0_3 = (uint64_t)sym__rotl32((uint32_t)tmp_2b380_2, 15);
                uint32_t tmp_24d00_3 = stack_m40;
                uint32_t tmp_20380_2 = tmp_24d00_3 ^ stack_m88 * (uint32_t)X0_3;
                stack_m40 = tmp_20380_2;
                uint32_t tmp_24d00_4 = stack_m40;
                uint64_t X0_5 = (uint64_t)sym__rotl32((uint32_t)tmp_24d00_4, 13);
                stack_m40 = (uint32_t)X0_5;
                uint32_t tmp_24d00_5 = stack_m40;
                uint32_t tmp_2a000_7 = 0xe6546b64;
                stack_m40 = tmp_24d00_5 * 5 + tmp_2a000_7;
                {
                    uint64_t X8_21 = stack_m64;
                    stack_m64 = X8_21 + 1;
                }
            }
        }
        {
            uint32_t stack_m84_3;
            uint8_t* stack_m80 = (uint8_t*)(stack_m24 + stack_m56 * 4);
            uint32_t stack_m84 = 0;
            X8_3 = stack_m32;
            X8_3 &= 3;
            uint64_t stack_m104 = X8_3;
            uint8_t TMPZR_7 = X8_3 == 1;
            uint8_t ZR_3 = TMPZR_7;
            stack_m84_3 = stack_m84;
            if (!ZR_3) {
                uint32_t stack_m84_2;
                uint64_t X8_28 = stack_m104;
                uint8_t TMPZR_8 = X8_28 == 2;
                uint8_t ZR_4 = TMPZR_8;
                stack_m84_2 = stack_m84;
                if (!ZR_4) {
                    uint64_t X8_30 = stack_m104;
                    uint8_t TMPZR_9 = X8_30 == 3;
                    uint8_t ZR_5 = TMPZR_9;
                    uint8_t tmp_a00_1 = !ZR_5;
                    if (tmp_a00_1) {
                        goto L3;
                    } else {
                        uint8_t tmp_25500_1 = *(uint8_t*)((uint64_t)stack_m80 + 2);
                        uint32_t tmp_20380_3 = stack_m84 ^ (uint32_t)tmp_25500_1 << 16;
                        stack_m84_2 = tmp_20380_3;
                    }
                }
                {
                    uint8_t tmp_25500_3 = *(uint8_t*)((uint64_t)stack_m80 + 1);
                    uint32_t tmp_20380_5 = stack_m84_2 ^ (uint32_t)tmp_25500_3 << 8;
                    stack_m84_3 = tmp_20380_5;
                }
            }
            {
                uint8_t tmp_25500_5 = *stack_m80;
                uint32_t tmp_2b380_5 = stack_m92 * (stack_m84_3 ^ (uint32_t)tmp_25500_5);
                uint64_t X0_7 = (uint64_t)sym__rotl32((uint32_t)tmp_2b380_5, 15);
                uint32_t tmp_24c00_18 = stack_m88 * (uint32_t)X0_7;
                uint32_t tmp_24d00_6 = stack_m40;
                uint32_t tmp_20380_8 = tmp_24d00_6 ^ tmp_24c00_18;
                stack_m40 = tmp_20380_8;
            }
            {
L3: ;
                X8_3 = stack_m32;
                uint64_t X9_24 = X8_3;
                uint32_t tmp_24d00_8 = stack_m40;
                stack_m40 = (uint32_t)X9_24 ^ tmp_24d00_8;
                uint32_t tmp_24d00_9 = stack_m40;
                uint32_t tmp_24d00_10 = stack_m40;
                stack_m40 = tmp_24d00_9 >> 16 ^ tmp_24d00_10;
                uint32_t tmp_24d00_11 = stack_m40;
                stack_m40 = tmp_24d00_11 * 0x85ebca6b;
                uint32_t tmp_24d00_12 = stack_m40;
                uint32_t tmp_24d00_13 = stack_m40;
                stack_m40 = tmp_24d00_12 >> 13 ^ tmp_24d00_13;
                uint32_t tmp_24d00_14 = stack_m40;
                stack_m40 = tmp_24d00_14 * 0xc2b2ae35;
                uint32_t tmp_24d00_15 = stack_m40;
                uint32_t tmp_24d00_16 = stack_m40;
                stack_m40 = tmp_24d00_15 >> 16 ^ tmp_24d00_16;
                uint32_t tmp_24d00_17 = stack_m40;
                return tmp_24d00_17;
            }
        }
    }
}

