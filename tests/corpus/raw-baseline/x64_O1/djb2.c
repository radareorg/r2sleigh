uint64_t sym__djb2(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 41 source obligations: 26 rendered, 15 elided, 0 refused; 22 statements rendered */
    {
        uint64_t RAX_1;
        RAX_1 = 0x1505;
        uint64_t tmp_70500_1 = RSI_0;
        uint8_t ZF_1 = tmp_70500_1 == 0;
        if (!ZF_1) {
            uint64_t RCX_1;
            RCX_1 = (uint64_t)0;
            for (; ; ) {
                uint32_t tmp_lane_1000005e0_0_3_1 = (uint32_t)RAX_1;
                uint32_t tmp_lane_1000005e0_4_6_1 = tmp_lane_1000005e0_0_3_1 << 5;
                uint32_t tmp_lane_1000005e0_28_9_1 = (uint32_t)RAX_1;
                uint32_t tmp_lane_1000005e0_2a_a_1 = tmp_lane_1000005e0_4_6_1 + tmp_lane_1000005e0_28_9_1;
                uint8_t tmp_11e00_2 = ((uint8_t*)RDI_0)[RCX_1];
                uint32_t tmp_lane_1000005e0_35_c_1 = (uint32_t)tmp_11e00_2;
                uint32_t tmp_lane_1000005e0_39_f_1 = tmp_lane_1000005e0_35_c_1 + tmp_lane_1000005e0_2a_a_1;
                RAX_1 = (uint64_t)(uint32_t)tmp_lane_1000005e0_39_f_1;
                RCX_1++;
                uint64_t tmp_3f080_2 = RSI_0;
                uint8_t ZF_8 = tmp_3f080_2 == RCX_1;
                if (ZF_8) {
                    break;
                }
            }
        }
        return RAX_1;
    }
}

