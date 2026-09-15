uint32_t sym__sdbm(uint64_t X0_0, uint64_t X1_0)
{
    /* r2dec proof: no individual construct is marked; 76 source obligations: 35 rendered, 41 elided, 0 refused; 27 statements rendered */
    {
        uint64_t stack_m32;
        uint32_t stack_m20;
        uint64_t stack_m16;
        uint8_t* stack_m8;
        stack_m8 = (uint8_t*)X0_0;
        stack_m16 = X1_0;
        stack_m20 = 0;
        stack_m32 = 0;
        for (; ; ) {
            uint64_t tmp_3e680_2 = stack_m16;
            uint8_t TMPCY_2 = tmp_3e680_2 <= stack_m32;
            if (TMPCY_2) {
                break;
            } else {
                uint32_t tmp_12280_3;
                uint8_t tmp_25600_2 = stack_m8[stack_m32];
                uint32_t tmp_12180_2 = stack_m20 << 6;
                uint32_t tmp_lane_1000006f0_f_1_1 = (uint32_t)tmp_25600_2;
                tmp_12280_3 = tmp_lane_1000006f0_f_1_1 + tmp_12180_2;
                uint32_t tmp_12180_3 = stack_m20 << 16;
                tmp_12280_3 += tmp_12180_3;
                uint32_t tmp_3e480_2 = stack_m20;
                uint32_t tmp_3e580_2 = tmp_12280_3 - tmp_3e480_2;
                stack_m20 = tmp_3e580_2;
                {
                    uint64_t tmp_11f80_2 = stack_m32 + 1;
                    uint64_t X8_10 = tmp_11f80_2;
                    stack_m32 = X8_10;
                }
            }
        }
        {
            return stack_m20;
        }
    }
}

