uint32_t sym__crc32_bitwise(uint64_t RDI_0, uint64_t RSI_0)
{
    /* r2dec proof: no individual construct is marked; 101 source obligations: 47 rendered, 54 elided, 0 refused; 38 statements rendered */
    {
        uint64_t stack_m40;
        uint32_t stack_m28;
        uint64_t stack_m24;
        uint8_t* stack_m16;
        stack_m16 = (uint8_t*)RDI_0;
        stack_m24 = RSI_0;
        stack_m28 = 0xffffffff;
        stack_m40 = 0;
        for (; ; ) {
            uint64_t RAX_2 = stack_m40;
            uint64_t tmp_3f800_2 = stack_m24;
            if (tmp_3f800_2 <= RAX_2) {
                break;
            } else {
                uint32_t stack_m44;
                uint64_t RCX_2 = stack_m40;
                uint8_t tmp_11e00_2 = stack_m16[RCX_2];
                uint32_t tmp_lane_100000815_f_2_1 = (uint32_t)tmp_11e00_2 ^ stack_m28;
                stack_m28 = tmp_lane_100000815_f_2_1;
                stack_m44 = 0;
                for (; ; ) {
                    uint32_t tmp_3e900_3 = stack_m44;
                    uint8_t tmp_12e80_3 = 8 <= (int32_t)tmp_3e900_3;
                    if (tmp_12e80_3) {
                        break;
                    } else {
                        uint32_t tmp_lane_100000834_7_7_1 = stack_m28 >> 1;
                        uint32_t tmp_lane_100000834_15_b_1 = stack_m28 & 1;
                        uint32_t tmp_lane_100000834_29_12_1 = -tmp_lane_100000834_15_b_1;
                        uint32_t tmp_lane_100000834_33_15_1 = tmp_lane_100000834_29_12_1 & 0xedb88320;
                        uint32_t tmp_lane_100000834_3d_19_1 = tmp_lane_100000834_7_7_1 ^ tmp_lane_100000834_33_15_1;
                        stack_m28 = tmp_lane_100000834_3d_19_1;
                        uint32_t tmp_lane_100000834_4e_1e_1 = stack_m44 + 1;
                        stack_m44 = tmp_lane_100000834_4e_1e_1;
                    }
                }
                {
                    uint64_t RAX_13;
                    RAX_13 = stack_m40;
                    RAX_13++;
                    stack_m40 = RAX_13;
                }
            }
        }
        {
            uint32_t tmp_lane_100000869_6_23_1 = stack_m28 ^ 0xffffffff;
            return tmp_lane_100000869_6_23_1;
        }
    }
}

