uint32_t sym__unaligned_words(uint64_t X0_0, uint64_t X1_0)
{
    /* r2dec proof: no individual construct is marked; 108 source obligations: 66 rendered, 42 elided, 0 refused; 34 statements rendered */
    {
        uint64_t stack_m16;
        uint8_t* stack_m8;
        uint32_t stack_m20;
        uint64_t stack_m32;
        stack_m8 = (uint8_t*)X0_0;
        stack_m16 = X1_0;
        uint32_t tmp_2a000_2 = 0x9e3779b9;
        stack_m20 = tmp_2a000_2;
        stack_m32 = 0;
        for (; ; ) {
            uint64_t X8_5 = stack_m32 + 8;
            uint64_t tmp_3e680_2 = stack_m16;
            uint8_t TMPCY_3 = tmp_3e680_2 <= X8_5;
            uint8_t TMPZR_3 = X8_5 == tmp_3e680_2;
            uint8_t tmp_e80_2 = TMPCY_3 && !TMPZR_3;
            if (tmp_e80_2) {
                break;
            } else {
                uint32_t tmp_24d00_2 = *(uint32_t*)(stack_m32 + (uint64_t)stack_m8 + 1);
                uint32_t tmp_2a000_5 = 0x1000193;
                stack_m20 = tmp_2a000_5 * (tmp_24d00_2 ^ stack_m20);
                {
                    uint64_t X8_13 = stack_m32;
                    stack_m32 = X8_13 + 7;
                }
            }
        }
        {
            for (; ; ) {
                uint64_t X8_16 = stack_m32;
                uint64_t tmp_3e680_4 = stack_m16;
                uint8_t TMPCY_7 = tmp_3e680_4 <= X8_16;
                if (TMPCY_7) {
                    break;
                } else {
                    uint8_t tmp_25600_2 = stack_m8[stack_m32];
                    uint32_t tmp_2a000_8 = 0x1000193;
                    stack_m20 = (stack_m20 ^ (uint32_t)tmp_25600_2) * tmp_2a000_8;
                    {
                        uint64_t X8_21 = stack_m32;
                        stack_m32 = X8_21 + 1;
                    }
                }
            }
            {
                return stack_m20;
            }
        }
    }
}

