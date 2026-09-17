uint32_t sym__sdbm(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 47 source obligations: 28 rendered, 19 elided, 0 refused; 15 statements rendered */
    if (RSI_0 == 0) {
        return 0;
    } else {
        uint64_t RCX_1;
        uint64_t RAX_1;
        uint32_t tmp_lane_100000610_10_b_1;
        RCX_1 = (uint64_t)0;
        RAX_1 = (uint64_t)0;
        for (; ; ) {
            uint8_t tmp_11e00_2 = ((uint8_t*)RDI_0)[RCX_1];
            tmp_lane_100000610_10_b_1 = (uint32_t)tmp_11e00_2 + (uint32_t)((uint64_t)(int32_t)RAX_1 * 0x1003f);
            RAX_1 = (uint64_t)(uint32_t)tmp_lane_100000610_10_b_1;
            RCX_1++;
            if (RSI_0 == RCX_1) {
                break;
            }
        }
        return tmp_lane_100000610_10_b_1;
    }
}

