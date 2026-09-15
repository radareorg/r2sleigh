uint32_t sym__fnv1a32(uint64_t X0_0, uint64_t X1_0)
{
    /* r2dec proof: no individual construct is marked; 72 source obligations: 39 rendered, 33 elided, 0 refused; 29 statements rendered */
    {
        uint64_t stack_m32;
        uint32_t stack_m20;
        uint64_t stack_m16;
        uint8_t* stack_m8;
        uint32_t tmp_24c00_3;
        stack_m8 = (uint8_t*)X0_0;
        stack_m16 = X1_0;
        uint32_t tmp_2a000_2 = 0x811c9dc5;
        stack_m20 = tmp_2a000_2;
        stack_m32 = 0;
        for (; ; ) {
            uint64_t tmp_3e680_2 = stack_m16;
            uint8_t TMPCY_2 = tmp_3e680_2 <= stack_m32;
            uint8_t CY_2 = TMPCY_2;
            if (CY_2) {
                break;
            } else {
                uint8_t tmp_25600_2 = stack_m8[stack_m32];
                tmp_24c00_3 = stack_m20;
                uint32_t tmp_20380_2 = (uint32_t)tmp_25600_2 ^ tmp_24c00_3;
                stack_m20 = tmp_20380_2;
                tmp_24c00_3 = stack_m20;
                uint32_t tmp_2a000_5 = 0x1000193;
                uint32_t tmp_2b380_2 = tmp_24c00_3 * tmp_2a000_5;
                stack_m20 = tmp_2b380_2;
                {
                    uint64_t tmp_11f80_2 = stack_m32 + 1;
                    uint64_t X8_12 = tmp_11f80_2;
                    stack_m32 = X8_12;
                }
            }
        }
        {
            tmp_24c00_3 = stack_m20;
            return tmp_24c00_3;
        }
    }
}

