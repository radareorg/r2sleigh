uint32_t sym__djb2(uint64_t X0_0, uint64_t X1_0)
{
    /* r2dec proof: no individual construct is marked; 59 source obligations: 37 rendered, 22 elided, 0 refused; 16 statements rendered */
    {
        uint64_t stack_m16;
        uint8_t* stack_m8;
        uint32_t stack_m20;
        uint64_t stack_m32;
        stack_m8 = (uint8_t*)X0_0;
        stack_m16 = X1_0;
        stack_m20 = 0x1505;
        for (stack_m32 = 0; ; stack_m32++) {
            uint8_t TMPCY_2 = stack_m16 <= stack_m32;
            if (TMPCY_2) {
                break;
            } else {
                stack_m20 += stack_m20 * 32;
                uint8_t tmp_25600_2 = stack_m8[stack_m32];
                stack_m20 += (uint32_t)tmp_25600_2;
            }
        }
        {
            return stack_m20;
        }
    }
}

