uint32_t sym__djb2(uint64_t X0_0, uint64_t X1_0)
{
    /* r2dec proof: no individual construct is marked; 69 source obligations: 37 rendered, 32 elided, 0 refused; 22 statements rendered */
    {
        uint64_t stack_m32;
        uint32_t stack_m20;
        uint64_t stack_m16;
        uint8_t* stack_m8;
        stack_m8 = (uint8_t*)X0_0;
        stack_m16 = X1_0;
        stack_m20 = 0x1505;
        stack_m32 = 0;
        for (; ; ) {
            uint64_t tmp_3e680_2 = stack_m16;
            uint8_t TMPCY_2 = tmp_3e680_2 <= stack_m32;
            if (TMPCY_2) {
                break;
            } else {
                uint32_t tmp_24c00_2 = stack_m20;
                uint32_t tmp_24c00_3 = stack_m20;
                uint32_t tmp_12280_2 = tmp_24c00_3 + tmp_24c00_2 * 32;
                uint8_t tmp_25600_2 = stack_m8[stack_m32];
                stack_m20 = (uint32_t)tmp_25600_2 + tmp_12280_2;
                {
                    uint64_t tmp_11f80_2 = stack_m32 + 1;
                    stack_m32 = tmp_11f80_2;
                }
            }
        }
        {
            uint32_t tmp_24c00_4 = stack_m20;
            return tmp_24c00_4;
        }
    }
}

