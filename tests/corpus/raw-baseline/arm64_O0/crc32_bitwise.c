uint32_t sym__crc32_bitwise(uint64_t X0_0, uint64_t X1_0)
{
    /* r2dec proof: no individual construct is marked; 92 source obligations: 57 rendered, 35 elided, 0 refused; 36 statements rendered */
    {
        uint64_t stack_m16;
        uint8_t* stack_m8;
        uint32_t stack_m20;
        uint64_t stack_m32;
        stack_m8 = (uint8_t*)X0_0;
        stack_m16 = X1_0;
        stack_m20 = 0xffffffff;
        stack_m32 = 0;
        for (; ; ) {
            uint64_t X8_3 = stack_m32;
            uint64_t tmp_3e680_2 = stack_m16;
            uint8_t TMPCY_2 = tmp_3e680_2 <= X8_3;
            uint8_t CY_2 = TMPCY_2;
            if (CY_2) {
                break;
            } else {
                uint32_t stack_m36;
                uint8_t tmp_25600_2 = stack_m8[stack_m32];
                uint64_t X9_4 = (uint64_t)(uint8_t)tmp_25600_2;
                uint32_t tmp_20380_2 = stack_m20 ^ (uint32_t)X9_4;
                stack_m20 = tmp_20380_2;
                stack_m36 = 0;
                for (; ; ) {
                    uint32_t tmp_24c00_4 = stack_m36;
                    uint8_t tmp_1100_3 = r2sleigh_int_sborrow_32(tmp_24c00_4, 8) == (int32_t)(tmp_24c00_4 - 8) < 0;
                    if (tmp_1100_3) {
                        break;
                    } else {
                        uint32_t tmp_24c00_5 = stack_m20;
                        uint32_t tmp_3e480_3 = stack_m20 & 1;
                        uint32_t tmp_3e580_3 = -tmp_3e480_3;
                        stack_m20 = tmp_24c00_5 >> 1 ^ (tmp_3e580_3 & 0xedb88320);
                        {
                            uint32_t tmp_24c00_7 = stack_m36;
                            stack_m36 = tmp_24c00_7 + 1;
                        }
                    }
                }
                {
                    uint64_t X8_19 = stack_m32;
                    stack_m32 = X8_19 + 1;
                }
            }
        }
        {
            uint32_t tmp_2b600_1 = ~stack_m20;
            return tmp_2b600_1;
        }
    }
}

