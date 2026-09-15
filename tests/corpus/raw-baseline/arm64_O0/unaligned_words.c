uint32_t sym__unaligned_words(uint64_t X0_0, uint64_t X1_0)
{
    /* r2dec proof: no individual construct is marked; 123 source obligations: 62 rendered, 61 elided, 0 refused; 47 statements rendered */
    {
        uint64_t stack_m32;
        uint32_t stack_m20;
        uint64_t stack_m16;
        uint8_t* stack_m8;
        stack_m8 = (uint8_t*)X0_0;
        stack_m16 = X1_0;
        uint32_t tmp_2a000_2 = 0x9e3779b9;
        stack_m20 = tmp_2a000_2;
        stack_m32 = 0;
        for (; ; ) {
            uint64_t tmp_11f80_2 = stack_m32 + 8;
            uint64_t X8_5 = tmp_11f80_2;
            uint64_t tmp_3e680_2 = stack_m16;
            uint8_t TMPCY_3 = tmp_3e680_2 <= X8_5;
            uint8_t TMPZR_3 = X8_5 == tmp_3e680_2;
            uint8_t ZR_2 = TMPZR_3;
            uint8_t CY_2 = TMPCY_3;
            if (!ZR_2 && CY_2) {
                break;
            } else {
                uint32_t stack_m36;
                uint64_t tmp_12380_2 = stack_m32;
                uint64_t tmp_12480_2 = (uint64_t)stack_m8 + tmp_12380_2;
                uint32_t tmp_24d00_2 = *(uint32_t*)(tmp_12480_2 + 1);
                stack_m36 = tmp_24d00_2;
                uint32_t tmp_24c00_3 = stack_m36;
                uint32_t tmp_20380_2 = stack_m20 ^ tmp_24c00_3;
                uint32_t tmp_2a000_5 = 0x1000193;
                uint32_t tmp_2b380_2 = tmp_20380_2 * tmp_2a000_5;
                stack_m20 = tmp_2b380_2;
                {
                    uint64_t tmp_11f80_3 = stack_m32 + 7;
                    uint64_t X8_14 = tmp_11f80_3;
                    stack_m32 = X8_14;
                }
            }
        }
        {
            for (; ; ) {
                uint64_t tmp_3e680_4 = stack_m16;
                uint8_t TMPCY_7 = tmp_3e680_4 <= stack_m32;
                uint8_t CY_4 = TMPCY_7;
                if (CY_4) {
                    break;
                } else {
                    uint8_t tmp_25600_2 = stack_m8[stack_m32];
                    uint32_t tmp_20380_4 = (uint32_t)tmp_25600_2 ^ stack_m20;
                    uint32_t tmp_2a000_8 = 0x1000193;
                    uint32_t tmp_2b380_4 = tmp_20380_4 * tmp_2a000_8;
                    stack_m20 = tmp_2b380_4;
                    {
                        uint64_t tmp_11f80_5 = stack_m32 + 1;
                        uint64_t X8_22 = tmp_11f80_5;
                        stack_m32 = X8_22;
                    }
                }
            }
            {
                return stack_m20;
            }
        }
    }
}

