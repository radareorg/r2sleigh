uint32_t sym__sdbm(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 48 source obligations: 28 rendered, 20 elided, 0 refused; 21 statements rendered */
    {
        uint64_t tmp_70500_1 = RSI_0;
        if (tmp_70500_1 == 0) {
            return 0;
        } else {
            uint64_t RCX_1;
            uint64_t RAX_1;
            uint32_t tmp_lane_100000610_10_b_1;
            RCX_1 = (uint64_t)0;
            RAX_1 = (uint64_t)0;
            for (; ; ) {
                uint8_t tmp_11e00_2 = ((uint8_t*)RDI_0)[RCX_1];
                uint32_t tmp_lane_100000610_3_6_1 = (uint32_t)tmp_11e00_2;
                uint64_t tmp_4c780_2 = (uint64_t)(int32_t)RAX_1 * 0x1003f;
                int32_t tmp_lane_100000610_8_8_1 = (int32_t)tmp_4c780_2;
                tmp_lane_100000610_10_b_1 = (uint32_t)tmp_lane_100000610_8_8_1 + tmp_lane_100000610_3_6_1;
                RAX_1 = (uint64_t)(uint32_t)tmp_lane_100000610_10_b_1;
                RCX_1++;
                uint64_t tmp_3f080_2 = RSI_0;
                uint8_t ZF_7 = tmp_3f080_2 == RCX_1;
                if (ZF_7) {
                    break;
                }
            }
            return tmp_lane_100000610_10_b_1;
        }
    }
}

