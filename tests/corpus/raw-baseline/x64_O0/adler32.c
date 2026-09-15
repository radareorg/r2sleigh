uint32_t sym__adler32(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 106 source obligations: 56 rendered, 50 elided, 0 refused; 33 statements rendered */
    {
        uint64_t stack_m40;
        uint32_t stack_m32;
        uint32_t stack_m28;
        uint64_t stack_m24;
        uint8_t* stack_m16;
        stack_m16 = (uint8_t*)RDI_0;
        stack_m24 = RSI_0;
        stack_m28 = 1;
        stack_m32 = 0;
        stack_m40 = 0;
        for (; ; ) {
            uint64_t RAX_2 = stack_m40;
            uint64_t tmp_3f800_2 = stack_m24;
            uint8_t CF_2 = RAX_2 < tmp_3f800_2;
            if (!CF_2) {
                break;
            } else {
                uint64_t RAX_10;
                uint8_t tmp_11e00_2 = stack_m16[stack_m40];
                uint32_t tmp_lane_10000071c_11_4_1 = (uint32_t)tmp_11e00_2 + stack_m28;
                uint64_t tmp_43f80_2 = (uint64_t)tmp_lane_10000071c_11_4_1;
                uint64_t tmp_44200_2 = tmp_43f80_2 % 0xfff1;
                stack_m28 = (uint32_t)tmp_44200_2;
                uint32_t tmp_lane_10000071c_3c_11_1 = stack_m32 + stack_m28;
                uint64_t tmp_43f80_3 = (uint64_t)tmp_lane_10000071c_3c_11_1;
                uint64_t tmp_44200_3 = tmp_43f80_3 % 0xfff1;
                uint32_t tmp_lane_10000071c_58_1a_1 = (uint32_t)tmp_44200_3;
                stack_m32 = tmp_lane_10000071c_58_1a_1;
                RAX_10 = stack_m40;
                RAX_10++;
                stack_m40 = RAX_10;
            }
        }
        {
            uint32_t tmp_lane_100000759_6_1e_1 = stack_m32 << 16;
            uint32_t tmp_lane_100000759_2e_21_1 = tmp_lane_100000759_6_1e_1 | stack_m28;
            return tmp_lane_100000759_2e_21_1;
        }
    }
}

