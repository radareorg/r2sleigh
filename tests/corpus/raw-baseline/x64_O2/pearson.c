uint32_t sym__pearson(uint64_t RDI_0, uint64_t RSI_0)
{
#define _pearson_tab__r2sleigh_addr 0x100001680ULL
    extern char _pearson_tab[];

    /* r2dec proof: no individual construct is marked; 125 source obligations: 99 rendered, 26 elided, 0 refused; 36 statements rendered; 1 data object type refused */
    {
        uint64_t RDX_1;
        if (RSI_0 == 0) {
            RDX_1 = (uint64_t)0;
        } else {
            uint64_t RCX_1;
            uint64_t RAX_2 = (uint64_t)(uint32_t)((uint32_t)RSI_0 & 3);
            if (4 <= RSI_0) {
                RSI_0 &= (uint64_t)-0x4;
                RCX_1 = (uint64_t)0;
                RDX_1 = (uint64_t)0;
                for (; ; ) {
                    uint8_t tmp_11e00_2 = ((uint8_t*)RDI_0)[RCX_1];
                    uint8_t tmp_11e00_3 = ((uint8_t*)RDI_0)[RCX_1 + 1];
                    uint8_t tmp_11e00_4 = *(uint8_t*)((uint64_t)(uint8_t)((uint8_t)RDX_1 ^ tmp_11e00_2) + (uint64_t)&_pearson_tab);
                    uint8_t tmp_11e00_5 = ((uint8_t*)RDI_0)[RCX_1 + 2];
                    uint8_t tmp_11e00_6 = *(uint8_t*)((uint64_t)(uint8_t)(tmp_11e00_3 ^ tmp_11e00_4) + (uint64_t)&_pearson_tab);
                    uint8_t tmp_11e00_7 = ((uint8_t*)RDI_0)[RCX_1 + 3];
                    uint8_t tmp_11e00_8 = *(uint8_t*)((uint64_t)(uint8_t)(tmp_11e00_5 ^ tmp_11e00_6) + (uint64_t)&_pearson_tab);
                    uint8_t tmp_11e00_9 = *(uint8_t*)((uint64_t)(uint8_t)(tmp_11e00_7 ^ tmp_11e00_8) + (uint64_t)&_pearson_tab);
                    RDX_1 = (uint64_t)(uint32_t)tmp_11e00_9;
                    RCX_1 += 4;
                    if (RSI_0 == RCX_1) {
                        break;
                    }
                }
            } else {
                RCX_1 = (uint64_t)0;
                RDX_1 = (uint64_t)0;
            }
            if (RAX_2 != 0) {
                uint64_t RCX_6;
                RDI_0 += RCX_1;
                RCX_6 = (uint64_t)0;
                for (; ; ) {
                    uint8_t tmp_11e00_12 = ((uint8_t*)RDI_0)[RCX_6];
                    uint8_t tmp_11e00_13 = *(uint8_t*)((uint64_t)(uint8_t)((uint8_t)RDX_1 ^ tmp_11e00_12) + (uint64_t)&_pearson_tab);
                    RDX_1 = (uint64_t)(uint32_t)tmp_11e00_13;
                    RCX_6++;
                    if (RAX_2 == RCX_6) {
                        break;
                    }
                }
            }
        }
        return (uint32_t)(uint8_t)RDX_1;
    }
}

