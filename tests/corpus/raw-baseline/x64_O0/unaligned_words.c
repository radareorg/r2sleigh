uint32_t sym__unaligned_words(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 105 source obligations: 54 rendered, 51 elided, 0 refused; 17 statements rendered */
    {
        uint64_t stack_m40;
        uint64_t stack_m24;
        uint8_t* stack_m16;
        int32_t stack_m28;
        stack_m16 = (uint8_t*)RDI_0;
        stack_m24 = RSI_0;
        stack_m28 = -1640531527;
        stack_m40 = 0;
        while (stack_m24 >= stack_m40 + 8) {
            int32_t tmp_11f00_2 = (int32_t)*(uint32_t*)(stack_m40 + (uint64_t)stack_m16 + 1);
            stack_m28 = (int32_t)((uint64_t)(int32_t)((uint32_t)tmp_11f00_2 ^ (uint32_t)stack_m28) * 0x1000193);
            stack_m40 += 7;
        }
        {
            while (stack_m40 < stack_m24) {
                uint8_t tmp_11e00_2 = stack_m16[stack_m40];
                stack_m28 = (int32_t)((uint64_t)(int32_t)((uint32_t)stack_m28 ^ (uint32_t)tmp_11e00_2) * 0x1000193);
                stack_m40++;
            }
            return (uint32_t)stack_m28;
        }
    }
}

