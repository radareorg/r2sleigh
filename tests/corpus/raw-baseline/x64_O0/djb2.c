uint32_t sym__djb2(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 75 source obligations: 33 rendered, 42 elided, 0 refused; 26 statements rendered */
    {
        uint64_t stack_m40;
        uint32_t stack_m28;
        uint64_t stack_m24;
        uint8_t* stack_m16;
        stack_m16 = (uint8_t*)RDI_0;
        stack_m24 = RSI_0;
        stack_m28 = 0x1505;
        stack_m40 = 0;
        for (; ; ) {
            uint64_t RAX_2 = stack_m40;
            uint64_t tmp_3f800_2 = stack_m24;
            uint8_t CF_2 = RAX_2 < tmp_3f800_2;
            if (!CF_2) {
                break;
            } else {
                uint64_t RAX_8;
                uint32_t tmp_lane_100000655_6_2_1 = stack_m28 << 5;
                uint32_t tmp_lane_100000655_30_5_1 = tmp_lane_100000655_6_2_1 + stack_m28;
                uint64_t RDX_2 = stack_m40;
                uint8_t tmp_11e00_2 = stack_m16[RDX_2];
                uint32_t tmp_lane_100000655_41_7_1 = (uint32_t)tmp_11e00_2;
                uint32_t tmp_lane_100000655_45_a_1 = tmp_lane_100000655_30_5_1 + tmp_lane_100000655_41_7_1;
                stack_m28 = tmp_lane_100000655_45_a_1;
                RAX_8 = stack_m40;
                RAX_8++;
                stack_m40 = RAX_8;
            }
        }
        return stack_m28;
    }
}

