uint32_t sym__crc32_bitwise(uint64_t X0_0, uint64_t X1_0)
{
    /* r2dec proof: no individual construct is marked; 92 source obligations: 57 rendered, 35 elided, 0 refused; 36 statements rendered */
    {
        uint64_t stack_m16;
        uint8_t* stack_m8;
        uint32_t space21249_3e794_1;
        uint64_t space21249_3e78c_1;
        stack_m8 = (uint8_t*)X0_0;
        stack_m16 = X1_0;
        space21249_3e794_1 = 0xffffffff;
        space21249_3e78c_1 = 0;
        for (; ; ) {
            uint64_t X8_3 = space21249_3e78c_1;
            uint64_t tmp_3e680_2 = stack_m16;
            uint8_t TMPCY_2 = tmp_3e680_2 <= X8_3;
            uint8_t CY_2 = TMPCY_2;
            if (CY_2) {
                break;
            } else {
                uint32_t space21249_3e788_3;
                uint8_t tmp_25600_2 = stack_m8[space21249_3e78c_1];
                uint64_t X9_4 = (uint64_t)(uint8_t)tmp_25600_2;
                uint32_t tmp_20380_2 = space21249_3e794_1 ^ (uint32_t)X9_4;
                space21249_3e794_1 = tmp_20380_2;
                space21249_3e788_3 = 0;
                for (; ; ) {
                    uint32_t tmp_24c00_4 = space21249_3e788_3;
                    uint8_t tmp_1100_3 = r2sleigh_int_sborrow_32(tmp_24c00_4, 8) == (int32_t)(tmp_24c00_4 - 8) < 0;
                    if (tmp_1100_3) {
                        break;
                    } else {
                        uint32_t tmp_24c00_5 = space21249_3e794_1;
                        uint32_t tmp_3e480_3 = space21249_3e794_1 & 1;
                        uint32_t tmp_3e580_3 = -tmp_3e480_3;
                        space21249_3e794_1 = tmp_24c00_5 >> 1 ^ (tmp_3e580_3 & 0xedb88320);
                        {
                            uint32_t tmp_24c00_7 = space21249_3e788_3;
                            space21249_3e788_3 = tmp_24c00_7 + 1;
                        }
                    }
                }
                {
                    uint64_t X8_19 = space21249_3e78c_1;
                    space21249_3e78c_1 = X8_19 + 1;
                }
            }
        }
        {
            uint32_t tmp_2b600_1 = ~space21249_3e794_1;
            return tmp_2b600_1;
        }
    }
}

