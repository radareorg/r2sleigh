uint32_t sym__fnv1a32(uint64_t X0_0, uint64_t X1_0)
{
    /* r2dec proof: no individual construct is marked; 61 source obligations: 37 rendered, 24 elided, 0 refused; 22 statements rendered */
    {
        uint64_t stack_m16;
        uint8_t* stack_m8;
        uint32_t space21249_3e790_1;
        uint64_t space21249_3e788_1;
        stack_m8 = (uint8_t*)X0_0;
        stack_m16 = X1_0;
        uint32_t tmp_2a000_2 = 0x811c9dc5;
        space21249_3e790_1 = tmp_2a000_2;
        space21249_3e788_1 = 0;
        for (; ; ) {
            uint64_t X8_4 = space21249_3e788_1;
            uint64_t tmp_3e680_2 = stack_m16;
            uint8_t TMPCY_2 = tmp_3e680_2 <= X8_4;
            if (TMPCY_2) {
                break;
            } else {
                uint8_t tmp_25600_2 = stack_m8[space21249_3e788_1];
                uint32_t tmp_2a000_5 = 0x1000193;
                space21249_3e790_1 = (space21249_3e790_1 ^ (uint32_t)tmp_25600_2) * tmp_2a000_5;
                {
                    uint64_t X8_11 = space21249_3e788_1;
                    space21249_3e788_1 = X8_11 + 1;
                }
            }
        }
        {
            uint32_t tmp_24c00_4 = space21249_3e790_1;
            return tmp_24c00_4;
        }
    }
}

