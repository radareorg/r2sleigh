uint64_t sym__fnv1a64(uint64_t X0_0, uint64_t X1_0)
{
    /* r2dec proof: no individual construct is marked; 78 source obligations: 39 rendered, 39 elided, 0 refused; 24 statements rendered */
    {
        uint64_t stack_m32;
        uint64_t stack_m24;
        uint64_t stack_m16;
        uint8_t* stack_m8;
        stack_m8 = (uint8_t*)X0_0;
        stack_m16 = X1_0;
        uint64_t X8_7 = 0xcbf29ce484222325U;
        stack_m24 = X8_7;
        stack_m32 = 0;
        for (; ; ) {
            uint64_t tmp_3e680_2 = stack_m16;
            uint8_t TMPCY_2 = tmp_3e680_2 <= stack_m32;
            uint8_t CY_2 = TMPCY_2;
            if (CY_2) {
                break;
            } else {
                uint8_t tmp_25600_2 = stack_m8[stack_m32];
                uint64_t X9_4 = (uint64_t)tmp_25600_2;
                stack_m24 = stack_m24 ^ X9_4;
                uint64_t X9_7 = 0x100000001b3;
                stack_m24 = stack_m24 * X9_7;
                {
                    uint64_t tmp_11f80_2 = stack_m32 + 1;
                    uint64_t X8_18 = tmp_11f80_2;
                    stack_m32 = X8_18;
                }
            }
        }
        {
            return stack_m24;
        }
    }
}

