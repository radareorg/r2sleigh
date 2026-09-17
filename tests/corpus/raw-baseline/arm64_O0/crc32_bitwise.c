uint32_t sym__crc32_bitwise(uint64_t X0_0, uint64_t X1_0)
{
    /* r2dec proof: no individual construct is marked; 84 source obligations: 53 rendered, 31 elided, 0 refused; 19 statements rendered */
    {
        uint64_t stack_m16;
        uint8_t* stack_m8;
        uint32_t stack_m20;
        uint64_t stack_m32;
        stack_m8 = (uint8_t*)X0_0;
        stack_m16 = X1_0;
        stack_m20 = 0xffffffff;
        for (stack_m32 = 0; stack_m32 < stack_m16; stack_m32++) {
            uint32_t stack_m36;
            uint8_t tmp_25600_2 = stack_m8[stack_m32];
            stack_m20 ^= (uint32_t)tmp_25600_2;
            for (stack_m36 = 0; ; stack_m36++) {
                uint32_t tmp_24c00_4 = stack_m36;
                if (r2sleigh_int_sborrow_32(tmp_24c00_4, 8) == (int32_t)(tmp_24c00_4 - 8) < 0) {
                    break;
                } else {
                    stack_m20 = stack_m20 >> 1 ^ (-(stack_m20 & 1) & 0xedb88320);
                }
            }
        }
        {
            return ~stack_m20;
        }
    }
}

