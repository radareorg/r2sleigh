uint32_t sym__murmur3_32(uint64_t X0_0, uint64_t X1_0, uint32_t W2_0)
{
    uint32_t sym__rotl32(uint32_t, uint8_t);

    /* r2dec proof: no individual construct is marked; 261 source obligations: 183 rendered, 78 elided, 0 refused; 65 statements rendered */
    {
        uint64_t stack_m56;
        uint32_t stack_m40;
        uint32_t stack_m36;
        uint64_t stack_m32;
        uint64_t stack_m24;
        uint64_t X8_3;
        uint64_t stack_m64;
        uint32_t tmp_24d00_5;
        uint32_t tmp_2a000_2 = 0xcc9e2d51;
        uint32_t tmp_2a000_4 = 0x1b873593;
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
            uint64_t X0_3 = (uint64_t)sym__rotl32((uint32_t)(tmp_25180_2 * tmp_2a000_2), 15);
            tmp_24d00_5 = stack_m40;
            stack_m40 = (uint32_t)X0_3 * tmp_2a000_4 ^ tmp_24d00_5;
            tmp_24d00_5 = stack_m40;
            uint64_t X0_5 = (uint64_t)sym__rotl32((uint32_t)tmp_24d00_5, 13);
            stack_m40 = (uint32_t)X0_5;
            tmp_24d00_5 = stack_m40;
            stack_m40 = tmp_24d00_5 * 5 - 0x19ab949c;
        }
        {
            uint32_t stack_m84;
            uint8_t* tmp_12480_1 = (uint8_t*)(stack_m24 + stack_m56 * 4);
            stack_m84 = 0;
            X8_3 = stack_m32;
            X8_3 &= 3;
            if (X8_3 != 1) {
                if (X8_3 != 2) {
                    if (X8_3 != 3) {
                        goto L3;
                    } else {
                        uint8_t tmp_25500_1 = tmp_12480_1[2];
                        stack_m84 ^= (uint32_t)tmp_25500_1 << 16;
                    }
                }
                {
                    uint8_t tmp_25500_3 = tmp_12480_1[1];
                    stack_m84 ^= (uint32_t)tmp_25500_3 << 8;
                }
            }
            {
                uint8_t tmp_25500_5 = *tmp_12480_1;
                uint64_t X0_7 = (uint64_t)sym__rotl32((uint32_t)(tmp_2a000_2 * ((uint32_t)tmp_25500_5 ^ stack_m84)), 15);
                tmp_24d00_5 = stack_m40;
                stack_m40 = (uint32_t)X0_7 * tmp_2a000_4 ^ tmp_24d00_5;
            }
            {
L3: ;
                X8_3 = stack_m32;
                tmp_24d00_5 = stack_m40;
                stack_m40 = (uint32_t)X8_3 ^ tmp_24d00_5;
                tmp_24d00_5 = stack_m40;
                tmp_24d00_5 = stack_m40;
                stack_m40 = tmp_24d00_5 >> 16 ^ tmp_24d00_5;
                tmp_24d00_5 = stack_m40;
                stack_m40 = tmp_24d00_5 * 0x85ebca6b;
                tmp_24d00_5 = stack_m40;
                tmp_24d00_5 = stack_m40;
                stack_m40 = tmp_24d00_5 >> 13 ^ tmp_24d00_5;
                tmp_24d00_5 = stack_m40;
                stack_m40 = tmp_24d00_5 * 0xc2b2ae35;
                tmp_24d00_5 = stack_m40;
                tmp_24d00_5 = stack_m40;
                stack_m40 = tmp_24d00_5 >> 16 ^ tmp_24d00_5;
                tmp_24d00_5 = stack_m40;
                return tmp_24d00_5;
            }
        }
    }
}

