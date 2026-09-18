uint64_t sym__adler32(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 75 source obligations: 54 rendered, 21 elided, 0 refused; 22 statements rendered */
    if (RSI_0 == 0) {
        return 1;
    } else {
        uint32_t R8_1;
        uint64_t RCX_1;
        uint64_t RAX_1;
        uint32_t tmp_lane_100000650_49_11_1;
        uint32_t tmp_lane_100000650_94_1b_1;
        R8_1 = 1;
        RCX_1 = (uint64_t)0;
        RAX_1 = (uint64_t)0;
        for (; ; ) {
            uint8_t tmp_11e00_2 = ((uint8_t*)RDI_0)[RCX_1];
            uint32_t tmp_lane_100000650_7_9_1 = (uint32_t)tmp_11e00_2 + R8_1;
            tmp_lane_100000650_49_11_1 = tmp_lane_100000650_7_9_1 - (uint32_t)((uint64_t)(int32_t)((uint64_t)tmp_lane_100000650_7_9_1 * 0x80078071 >> 47) * 0xfff1);
            R8_1 = tmp_lane_100000650_49_11_1;
            uint32_t tmp_lane_100000650_53_15_1 = (uint32_t)RAX_1 + tmp_lane_100000650_49_11_1;
            tmp_lane_100000650_94_1b_1 = tmp_lane_100000650_53_15_1 - (uint32_t)((uint64_t)(int32_t)((uint64_t)tmp_lane_100000650_53_15_1 * 0x80078071 >> 47) * 0xfff1);
            RAX_1 = (uint64_t)tmp_lane_100000650_94_1b_1;
            RCX_1++;
            if (RSI_0 == RCX_1) {
                break;
            }
        }
        return (uint64_t)(tmp_lane_100000650_94_1b_1 << 16 | tmp_lane_100000650_49_11_1);
    }
}

