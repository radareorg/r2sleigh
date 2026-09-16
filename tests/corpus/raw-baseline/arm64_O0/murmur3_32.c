uint32_t sym__murmur3_32(uint64_t X0_0, uint64_t X1_0, uint32_t W2_0)
{
    uint32_t sym__rotl32(uint32_t, uint8_t);

    /* r2dec proof: no individual construct is marked; 314 source obligations: 231 rendered, 83 elided, 0 refused; 70 statements rendered */
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
        for (stack_m64 = 0; stack_m64 < stack_m56; stack_m64++) {
            uint32_t tmp_25180_2 = ((uint32_t*)stack_m24)[stack_m64];
            uint64_t X0_3 = (uint64_t)sym__rotl32((uint32_t)(stack_m92 * tmp_25180_2), 15);
            uint32_t tmp_24d00_3 = stack_m40;
            stack_m40 = tmp_24d00_3 ^ stack_m88 * (uint32_t)X0_3;
            uint32_t tmp_24d00_4 = stack_m40;
            uint64_t X0_5 = (uint64_t)sym__rotl32((uint32_t)tmp_24d00_4, 13);
            stack_m40 = (uint32_t)X0_5;
            uint32_t tmp_24d00_5 = stack_m40;
            stack_m40 = tmp_24d00_5 * 5 - 0x19ab949c;
        }
        {
            uint32_t stack_m84_3;
            uint8_t* stack_m80 = (uint8_t*)(stack_m24 + stack_m56 * 4);
            uint32_t stack_m84 = 0;
            X8_3 = stack_m32;
            X8_3 &= 3;
            uint64_t stack_m104 = X8_3;
            stack_m84_3 = stack_m84;
            if (X8_3 != 1) {
                uint32_t stack_m84_2;
                stack_m84_2 = stack_m84;
                if (stack_m104 != 2) {
                    if (stack_m104 != 3) {
                        goto L3;
                    } else {
                        uint8_t tmp_25500_1 = *(uint8_t*)((uint64_t)stack_m80 + 2);
                        stack_m84_2 = stack_m84 ^ (uint32_t)tmp_25500_1 << 16;
                    }
                }
                {
                    uint8_t tmp_25500_3 = *(uint8_t*)((uint64_t)stack_m80 + 1);
                    stack_m84_3 = stack_m84_2 ^ (uint32_t)tmp_25500_3 << 8;
                }
            }
            {
                uint8_t tmp_25500_5 = *stack_m80;
                uint64_t X0_7 = (uint64_t)sym__rotl32((uint32_t)(stack_m92 * (stack_m84_3 ^ (uint32_t)tmp_25500_5)), 15);
                uint32_t tmp_24d00_6 = stack_m40;
                stack_m40 = tmp_24d00_6 ^ stack_m88 * (uint32_t)X0_7;
            }
            {
L3: ;
                X8_3 = stack_m32;
                uint32_t tmp_24d00_8 = stack_m40;
                stack_m40 = (uint32_t)X8_3 ^ tmp_24d00_8;
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

