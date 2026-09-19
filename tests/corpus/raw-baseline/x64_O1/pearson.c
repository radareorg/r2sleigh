uint32_t sym__pearson(uint64_t RDI_0, uint64_t RSI_0)
{
#define _pearson_tab__r2sleigh_addr 0x100000f70ULL
    extern char _pearson_tab[];

    /* r2dec proof: no individual construct is marked; 47 source obligations: 32 rendered, 15 elided, 0 refused; 14 statements rendered; 1 data object type refused */
    {
        uint64_t RCX_1;
        if (RSI_0 == 0) {
            RCX_1 = (uint64_t)0;
        } else {
            uint64_t RAX_1;
            RAX_1 = (uint64_t)0;
            RCX_1 = (uint64_t)0;
            for (; ; ) {
                uint8_t tmp_11e00_2 = ((uint8_t*)RDI_0)[RAX_1];
                uint8_t tmp_11e00_3 = *(uint8_t*)((uint64_t)(uint8_t)((uint8_t)RCX_1 ^ tmp_11e00_2) + (uint64_t)&_pearson_tab);
                RCX_1 = (uint64_t)tmp_11e00_3;
                RAX_1++;
                if (RSI_0 == RAX_1) {
                    break;
                }
            }
        }
        return (uint32_t)(uint8_t)RCX_1;
    }
}

