uint64_t sym__djb2(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 120 source obligations: 91 rendered, 29 elided, 0 refused; 34 statements rendered */
    if (RSI_0 == 0) {
        return 0x1505;
    } else {
        uint64_t RAX_1;
        uint64_t RDX_1;
        uint64_t RCX_2 = (uint64_t)((uint32_t)RSI_0 & 3);
        if (4 <= RSI_0) {
            RSI_0 &= (uint64_t)-0x4;
            RAX_1 = 0x1505;
            RDX_1 = (uint64_t)0;
            for (; ; ) {
                uint8_t tmp_11e00_2 = ((uint8_t*)RDI_0)[RDX_1];
                uint32_t tmp_lane_1000006f0_39_17_1 = (uint32_t)tmp_11e00_2 + ((uint32_t)RAX_1 * 32 + (uint32_t)RAX_1);
                uint8_t tmp_11e00_3 = ((uint8_t*)RDI_0)[RDX_1 + 1];
                uint32_t tmp_lane_1000006f0_79_23_1 = (uint32_t)tmp_11e00_3 + tmp_lane_1000006f0_39_17_1 + tmp_lane_1000006f0_39_17_1 * 32;
                uint8_t tmp_11e00_4 = ((uint8_t*)RDI_0)[RDX_1 + 2];
                uint32_t tmp_lane_1000006f0_b9_2f_1 = (uint32_t)tmp_11e00_4 + tmp_lane_1000006f0_79_23_1 + tmp_lane_1000006f0_79_23_1 * 32;
                uint8_t tmp_11e00_5 = ((uint8_t*)RDI_0)[RDX_1 + 3];
                RAX_1 = (uint64_t)((uint32_t)tmp_11e00_5 + tmp_lane_1000006f0_b9_2f_1 + tmp_lane_1000006f0_b9_2f_1 * 32);
                RDX_1 += 4;
                if (RSI_0 == RDX_1) {
                    break;
                }
            }
        } else {
            RAX_1 = 0x1505;
            RDX_1 = (uint64_t)0;
        }
        {
            if (RCX_2 != 0) {
                uint64_t RDX_6;
                RDI_0 += RDX_1;
                RDX_6 = (uint64_t)0;
                for (; ; ) {
                    uint8_t tmp_11e00_8 = ((uint8_t*)RDI_0)[RDX_6];
                    RAX_1 = (uint64_t)((uint32_t)tmp_11e00_8 + ((uint32_t)RAX_1 * 32 + (uint32_t)RAX_1));
                    RDX_6++;
                    if (RCX_2 == RDX_6) {
                        break;
                    }
                }
            }
            return RAX_1;
        }
    }
}

