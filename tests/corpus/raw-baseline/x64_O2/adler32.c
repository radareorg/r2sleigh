uint64_t sym__adler32(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 158 source obligations: 131 rendered, 27 elided, 0 refused; 36 statements rendered */
    if (RSI_0 == 0) {
        return 1;
    } else {
        uint32_t RCX_1;
        uint64_t RDX_1;
        uint64_t RAX_1;
        if (RSI_0 != 1) {
            uint64_t R8_2 = RSI_0 & (uint64_t)-0x2;
            RCX_1 = 1;
            RDX_1 = (uint64_t)0;
            RAX_1 = (uint64_t)0;
            for (; ; ) {
                uint8_t tmp_11e00_2 = ((uint8_t*)RDI_0)[RDX_1];
                uint32_t tmp_lane_100000850_7_f_1 = (uint32_t)tmp_11e00_2 + (uint32_t)RCX_1;
                uint32_t tmp_lane_100000850_48_15_1 = tmp_lane_100000850_7_f_1 - (uint32_t)((uint64_t)(int32_t)((uint64_t)tmp_lane_100000850_7_f_1 * 0x80078071 >> 47) * 0xfff1);
                uint32_t tmp_lane_100000850_52_19_1 = (uint32_t)RAX_1 + tmp_lane_100000850_48_15_1;
                uint8_t tmp_11e00_3 = ((uint8_t*)RDI_0)[RDX_1 + 1];
                uint32_t tmp_lane_100000850_a3_24_1 = (uint32_t)tmp_11e00_3 + tmp_lane_100000850_48_15_1;
                uint32_t tmp_lane_100000850_e4_2a_1 = tmp_lane_100000850_a3_24_1 - (uint32_t)((uint64_t)(int32_t)((uint64_t)tmp_lane_100000850_a3_24_1 * 0x2001f >> 33) * 0xfff1);
                RCX_1 = (uint32_t)tmp_lane_100000850_e4_2a_1;
                uint32_t tmp_lane_100000850_ee_2e_1 = tmp_lane_100000850_52_19_1 + tmp_lane_100000850_e4_2a_1 - (uint32_t)((uint64_t)(int32_t)((uint64_t)tmp_lane_100000850_52_19_1 * 0x80078071 >> 47) * 0xfff1);
                RAX_1 = (uint64_t)(uint32_t)(tmp_lane_100000850_ee_2e_1 - (uint32_t)((uint64_t)(int32_t)((uint64_t)tmp_lane_100000850_ee_2e_1 * 0x2001f >> 33) * 0xfff1));
                RDX_1 += 2;
                if (R8_2 == RDX_1) {
                    break;
                }
            }
        } else {
            RCX_1 = 1;
            RDX_1 = (uint64_t)0;
            RAX_1 = (uint64_t)0;
        }
        {
            if ((uint8_t)((uint8_t)RSI_0 & 1) != 0) {
                uint8_t tmp_11e00_5 = ((uint8_t*)RDI_0)[RDX_1];
                uint32_t tmp_lane_1000008c5_7_3a_1 = (uint32_t)tmp_11e00_5 + (uint32_t)RCX_1;
                int64_t RDX_7 = 0x80078071;
                uint32_t tmp_lane_1000008c5_49_40_1 = tmp_lane_1000008c5_7_3a_1 - (uint32_t)((uint64_t)(int32_t)((uint64_t)tmp_lane_1000008c5_7_3a_1 * (uint64_t)RDX_7 >> 47) * 0xfff1);
                RCX_1 = (uint32_t)tmp_lane_1000008c5_49_40_1;
                uint32_t tmp_lane_1000008c5_53_44_1 = (uint32_t)RAX_1 + tmp_lane_1000008c5_49_40_1;
                RAX_1 = (uint64_t)(uint32_t)(tmp_lane_1000008c5_53_44_1 - (uint32_t)((uint64_t)(int32_t)((uint64_t)tmp_lane_1000008c5_53_44_1 * (uint64_t)RDX_7 >> 47) * 0xfff1));
            }
            return (uint64_t)((uint32_t)RAX_1 << 16 | (uint32_t)RCX_1);
        }
    }
}

