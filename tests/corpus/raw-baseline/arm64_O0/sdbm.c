uint32_t sym__sdbm(uint64_t X0_0, uint64_t X1_0)
{
    /* r2dec proof: no individual construct is marked; 64 source obligations: 39 rendered, 25 elided, 0 refused; 25 statements rendered */
    {
        uint64_t stack_m16;
        uint8_t* stack_m8;
        uint32_t space21249_3e790_1;
        uint64_t space21249_3e788_1;
        stack_m8 = (uint8_t*)X0_0;
        stack_m16 = X1_0;
        space21249_3e790_1 = 0;
        space21249_3e788_1 = 0;
        for (; ; ) {
            uint64_t X8_2 = space21249_3e788_1;
            uint64_t tmp_3e680_2 = stack_m16;
            uint8_t TMPCY_2 = tmp_3e680_2 <= X8_2;
            if (TMPCY_2) {
                break;
            } else {
                uint32_t tmp_12280_3;
                uint8_t tmp_25600_2 = stack_m8[space21249_3e788_1];
                tmp_12280_3 = (uint32_t)tmp_25600_2 + space21249_3e790_1 * 64;
                tmp_12280_3 += space21249_3e790_1 * 0x10000;
                uint32_t tmp_24c00_4 = space21249_3e790_1;
                uint32_t tmp_3e480_2 = tmp_24c00_4;
                space21249_3e790_1 = tmp_12280_3 - tmp_3e480_2;
                {
                    uint64_t X8_9 = space21249_3e788_1;
                    space21249_3e788_1 = X8_9 + 1;
                }
            }
        }
        {
            uint32_t tmp_24c00_5 = space21249_3e790_1;
            return tmp_24c00_5;
        }
    }
}

