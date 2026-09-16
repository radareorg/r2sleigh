uint32_t sym__pearson(uint64_t RDI_0, uint64_t RSI_0)
{
#define _pearson_tab__r2sleigh_addr 0x100000f70ULL
    extern char _pearson_tab[];

    /* r2dec proof: no individual construct is marked; 48 source obligations: 32 rendered, 16 elided, 0 refused; 20 statements rendered; 1 data object type refused */
    {
        uint64_t RCX_6;
        uint64_t tmp_70500_1 = RSI_0;
        if (tmp_70500_1 == 0) {
            RCX_6 = (uint64_t)0;
        } else {
            uint64_t RAX_1;
            uint64_t RCX_1;
            RAX_1 = (uint64_t)0;
            RCX_1 = (uint64_t)0;
            for (; ; ) {
                uint8_t tmp_11e00_2 = ((uint8_t*)RDI_0)[RAX_1];
                uint8_t tmp_lane_100000cb0_5_7_1 = (uint8_t)((uint8_t)RCX_1 ^ tmp_11e00_2);
                uint8_t tmp_11e00_3 = *(uint8_t*)((uint64_t)tmp_lane_100000cb0_5_7_1 + (uint64_t)&_pearson_tab);
                RCX_1 = (uint64_t)(uint32_t)tmp_11e00_3;
                RAX_1++;
                uint64_t tmp_3f080_2 = RSI_0;
                uint8_t tmp_12800_2 = tmp_3f080_2 != RAX_1;
                if (!tmp_12800_2) {
                    break;
                }
            }
            RCX_6 = RCX_1;
        }
        return (uint32_t)(uint8_t)RCX_6;
    }
}

