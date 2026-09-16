uint64_t sym__fnv1a64(uint64_t X0_0, uint64_t X1_0)
{
    /* r2dec proof: no individual construct is marked; 67 source obligations: 45 rendered, 22 elided, 0 refused; 16 statements rendered */
    {
        uint64_t stack_m16;
        uint8_t* stack_m8;
        uint64_t stack_m24;
        uint64_t stack_m32;
        stack_m8 = (uint8_t*)X0_0;
        stack_m16 = X1_0;
        stack_m24 = 0xcbf29ce484222325U;
        for (stack_m32 = 0; ; stack_m32++) {
            uint8_t TMPCY_2 = stack_m16 <= stack_m32;
            if (TMPCY_2) {
                break;
            } else {
                uint8_t tmp_25600_2 = stack_m8[stack_m32];
                uint64_t X9_4 = (uint64_t)tmp_25600_2;
                stack_m24 = (stack_m24 ^ X9_4) * 0x100000001b3;
            }
        }
        {
            return stack_m24;
        }
    }
}

