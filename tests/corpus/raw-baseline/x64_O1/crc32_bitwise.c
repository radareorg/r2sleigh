uint32_t sym__crc32_bitwise(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 66 source obligations: 42 rendered, 24 elided, 0 refused; 23 statements rendered */
    if (RSI_0 == 0) {
        return 0;
    } else {
        uint64_t RAX_1;
        uint64_t RCX_1;
        uint32_t tmp_lane_100000740_2d_17_1;
        RAX_1 = 0xffffffff;
        RCX_1 = (uint64_t)0;
        for (; ; ) {
            uint32_t RDX_5;
            uint8_t tmp_11e00_2 = ((uint8_t*)RDI_0)[RCX_1];
            RAX_1 = (uint64_t)((uint32_t)tmp_11e00_2 ^ (uint32_t)RAX_1);
            RDX_5 = 8;
            for (; ; ) {
                tmp_lane_100000740_2d_17_1 = (uint32_t)RAX_1 >> 1 ^ (-((uint32_t)RAX_1 & 1) & 0xedb88320);
                RAX_1 = (uint64_t)tmp_lane_100000740_2d_17_1;
                uint32_t tmp_lane_100000740_36_1a_1 = RDX_5 - 1;
                RDX_5 = tmp_lane_100000740_36_1a_1;
                if (tmp_lane_100000740_36_1a_1 == 0) {
                    break;
                }
            }
            {
                RCX_1++;
                if (RCX_1 == RSI_0) {
                    break;
                }
            }
        }
        return ~tmp_lane_100000740_2d_17_1;
    }
}

