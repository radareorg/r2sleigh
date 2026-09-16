uint32_t sym__unaligned_words(uint64_t X0_0, uint64_t X1_0)
{
    /* r2dec proof: no individual construct is marked; 108 source obligations: 70 rendered, 38 elided, 0 refused; 20 statements rendered */
    {
        uint64_t stack_m16;
        uint8_t* stack_m8;
        uint32_t stack_m20;
        uint64_t stack_m32;
        stack_m8 = (uint8_t*)X0_0;
        stack_m16 = X1_0;
        stack_m20 = 0x9e3779b9;
        for (stack_m32 = 0; ; stack_m32 += 7) {
            uint64_t X8_5 = stack_m32 + 8;
            uint64_t tmp_3e680_2 = stack_m16;
            if (tmp_3e680_2 < X8_5) {
                break;
            } else {
                uint32_t tmp_24d00_2 = *(uint32_t*)(stack_m32 + (uint64_t)stack_m8 + 1);
                stack_m20 = (tmp_24d00_2 ^ stack_m20) * 0x1000193;
            }
        }
        {
            while (stack_m32 < stack_m16) {
                uint8_t tmp_25600_2 = stack_m8[stack_m32];
                stack_m20 = (stack_m20 ^ (uint32_t)tmp_25600_2) * 0x1000193;
                stack_m32++;
            }
            {
                return stack_m20;
            }
        }
    }
}

