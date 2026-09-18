uint32_t sym__murmur3_32(uint64_t X0_0, uint64_t X1_0, uint32_t W2_0)
{
    uint32_t sym__rotl32(uint32_t, uint8_t);

    /* r2dec proof: no individual construct is marked; 178 source obligations: 127 rendered, 51 elided, 0 refused; 32 statements rendered */
    {
        uint32_t stack_m36;
        uint64_t stack_m32;
        uint64_t stack_m24;
        uint32_t tmp_24d00_1;
        uint64_t stack_m64;
        stack_m24 = X0_0;
        stack_m32 = X1_0;
        stack_m36 = W2_0;
        tmp_24d00_1 = stack_m36;
        uint64_t tmp_42488_1 = stack_m32 / 4;
        uint64_t X8_4 = 0 ? 0 : tmp_42488_1;
        for (stack_m64 = 0; stack_m64 < X8_4; stack_m64++) {
            uint32_t tmp_25180_2 = ((uint32_t*)stack_m24)[stack_m64];
            uint32_t X0_3 = sym__rotl32((uint32_t)(tmp_25180_2 * 0xcc9e2d51), 15);
            uint32_t X0_5 = sym__rotl32((uint32_t)(tmp_24d00_1 ^ X0_3 * 0x1b873593), 13);
            tmp_24d00_1 = X0_5 * 5 - 0x19ab949c;
        }
        {
            uint32_t stack_m84;
            uint8_t* tmp_12480_1 = (uint8_t*)(stack_m24 + X8_4 * 4);
            stack_m84 = 0;
            switch (stack_m32 & 3) {
            case 3:
                {
                    uint8_t tmp_25500_1 = tmp_12480_1[2];
                    stack_m84 ^= (uint32_t)tmp_25500_1 << 16;
                }
            case 2:
                {
                    uint8_t tmp_25500_3 = tmp_12480_1[1];
                    stack_m84 ^= (uint32_t)tmp_25500_3 << 8;
                }
            case 1:
                {
                    uint8_t tmp_25500_5 = *tmp_12480_1;
                    uint32_t X0_7 = sym__rotl32((uint32_t)(((uint32_t)tmp_25500_5 ^ stack_m84) * 0xcc9e2d51), 15);
                    tmp_24d00_1 ^= X0_7 * 0x1b873593;
                }
            default:
                {
                    uint32_t tmp_20380_10 = (uint32_t)stack_m32 ^ tmp_24d00_1;
                    uint32_t tmp_2b380_8 = (tmp_20380_10 >> 16 ^ tmp_20380_10) * 0x85ebca6b;
                    uint32_t tmp_2b380_9 = (tmp_2b380_8 >> 13 ^ tmp_2b380_8) * 0xc2b2ae35;
                    return tmp_2b380_9 >> 16 ^ tmp_2b380_9;
                }
            }
        }
    }
}

