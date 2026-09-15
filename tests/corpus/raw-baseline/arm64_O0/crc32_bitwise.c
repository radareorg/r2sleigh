uint32_t sym__crc32_bitwise(uint64_t X0_0, uint64_t X1_0)
{
    /* r2dec proof: no individual construct is marked; 105 source obligations: 59 rendered, 46 elided, 0 refused; 37 statements rendered */
    {
        uint64_t stack_m32;
        uint32_t stack_m20;
        uint64_t stack_m16;
        uint8_t* stack_m8;
        stack_m8 = (uint8_t*)X0_0;
        stack_m16 = X1_0;
        stack_m20 = 0xffffffff;
        stack_m32 = 0;
        for (; ; ) {
            uint64_t tmp_3e680_2 = stack_m16;
            uint8_t TMPCY_2 = tmp_3e680_2 <= stack_m32;
            uint8_t CY_2 = TMPCY_2;
            if (CY_2) {
                break;
            } else {
                uint32_t stack_m36;
                uint8_t tmp_25600_2 = stack_m8[stack_m32];
                uint64_t X9_4 = (uint64_t)(uint8_t)tmp_25600_2;
                uint32_t tmp_24c00_2 = stack_m20;
                uint32_t tmp_20380_2 = (uint32_t)X9_4 ^ tmp_24c00_2;
                stack_m20 = tmp_20380_2;
                stack_m36 = 0;
                for (; ; ) {
                    uint8_t tmp_1100_3 = r2sleigh_int_sborrow_32(stack_m36, 8) == (int32_t)(stack_m36 - 8) < 0;
                    if (tmp_1100_3) {
                        break;
                    } else {
                        uint32_t tmp_24c00_5 = stack_m20;
                        uint32_t tmp_24c00_6 = stack_m20;
                        uint32_t tmp_3e480_3 = tmp_24c00_6 & 1;
                        uint32_t tmp_3e580_3 = -tmp_3e480_3;
                        stack_m20 = tmp_24c00_5 >> 1 ^ (tmp_3e580_3 & 0xedb88320);
                        {
                            uint32_t tmp_11b80_3 = stack_m36 + 1;
                            stack_m36 = tmp_11b80_3;
                        }
                    }
                }
                {
                    uint64_t tmp_11f80_2 = stack_m32 + 1;
                    stack_m32 = tmp_11f80_2;
                }
            }
        }
        {
            uint32_t tmp_24c00_8 = stack_m20;
            uint32_t tmp_2b600_1 = ~tmp_24c00_8;
            return tmp_2b600_1;
        }
    }
}

