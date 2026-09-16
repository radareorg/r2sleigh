uint32_t sym__pearson(uint64_t RDI_0, uint64_t RSI_0)
{
#define _pearson_tab__r2sleigh_addr 0x100001a50ULL
    extern char _pearson_tab[];

    /* r2dec proof: no individual construct is marked; 75 source obligations: 38 rendered, 37 elided, 0 refused; 14 statements rendered; 1 data object type refused */
    {
        uint64_t stack_m40;
        uint8_t stack_m25;
        uint64_t stack_m24;
        uint8_t* stack_m16;
        stack_m16 = (uint8_t*)RDI_0;
        stack_m24 = RSI_0;
        stack_m25 = 0;
        stack_m40 = 0;
        while (stack_m40 < stack_m24) {
            uint8_t tmp_11e00_3 = stack_m16[stack_m40];
            uint8_t tmp_11e00_4 = *(uint8_t*)((uint64_t)(int32_t)((uint32_t)stack_m25 ^ (uint32_t)tmp_11e00_3) + (uint64_t)&_pearson_tab);
            stack_m25 = tmp_11e00_4;
            stack_m40++;
        }
        return (uint32_t)stack_m25;
    }
}

