uint32_t sym__murmur3_32(uint64_t RDI_0, uint64_t RSI_0, uint32_t EDX_0)
{
    uint32_t sym__rotl32(uint32_t, uint8_t);

    /* r2dec proof: no individual construct is marked; 338 source obligations: 222 rendered, 116 elided, 0 refused; 95 statements rendered */
    {
        uint64_t stack_m56;
        uint64_t stack_m48;
        uint32_t stack_m32;
        uint32_t stack_m28;
        uint64_t stack_m24;
        uint64_t stack_m16;
        uint64_t tmp_11f80_1;
        uint32_t tmp_11f00_10;
        stack_m16 = RDI_0;
        stack_m24 = RSI_0;
        stack_m28 = EDX_0;
        uint32_t tmp_11f00_1 = stack_m28;
        stack_m32 = tmp_11f00_1;
        tmp_11f80_1 = stack_m24;
        stack_m48 = tmp_11f80_1 >> 2;
        stack_m56 = 0;
        while (stack_m56 < stack_m48) {
            int32_t stack_m60;
            int32_t tmp_11f00_3;
            tmp_11f00_3 = (int32_t)((uint32_t*)stack_m16)[stack_m56];
            stack_m60 = tmp_11f00_3;
            tmp_11f00_3 = (int32_t)stack_m60;
            stack_m60 = (int32_t)((uint64_t)tmp_11f00_3 * 0xffffffffcc9e2d51U);
            tmp_11f00_3 = (int32_t)stack_m60;
            uint32_t RAX_9 = sym__rotl32((uint32_t)tmp_11f00_3, 15);
            stack_m60 = (int32_t)RAX_9;
            tmp_11f00_3 = (int32_t)stack_m60;
            stack_m60 = (int32_t)((uint64_t)tmp_11f00_3 * 0x1b873593);
            tmp_11f00_3 = (int32_t)stack_m60;
            tmp_11f00_10 = stack_m32;
            stack_m32 = (uint32_t)tmp_11f00_3 ^ tmp_11f00_10;
            tmp_11f00_10 = stack_m32;
            uint32_t RAX_13 = sym__rotl32((uint32_t)tmp_11f00_10, 13);
            stack_m32 = (uint32_t)RAX_13;
            tmp_11f00_10 = stack_m32;
            stack_m32 = (uint32_t)((uint64_t)(int32_t)tmp_11f00_10 * 5) - 0x19ab949c;
            stack_m56++;
        }
        {
            uint64_t stack_m88;
            uint32_t stack_m76;
            uint64_t stack_m72;
            uint64_t RAX_21;
            uint64_t tmp_11f80_13;
            uint32_t tmp_11f00_11;
            stack_m72 = stack_m48 * 4 + stack_m16;
            stack_m76 = 0;
            tmp_11f80_1 = stack_m24;
            RAX_21 = (uint64_t)((uint32_t)tmp_11f80_1 & 3);
            stack_m88 = RAX_21;
            if (RAX_21 != 1) {
                RAX_21 = stack_m88;
                if (RAX_21 != 2) {
                    RAX_21 = stack_m88;
                    if (RAX_21 != 3) {
                        goto L3;
                    } else {
                        tmp_11f80_13 = stack_m72;
                        uint8_t tmp_11e00_1 = *(uint8_t*)(tmp_11f80_13 + 2);
                        tmp_11f00_11 = stack_m76;
                        stack_m76 = (uint32_t)tmp_11e00_1 << 16 ^ tmp_11f00_11;
                    }
                }
                {
                    tmp_11f80_13 = stack_m72;
                    uint8_t tmp_11e00_3 = *(uint8_t*)(tmp_11f80_13 + 1);
                    tmp_11f00_11 = stack_m76;
                    stack_m76 = (uint32_t)tmp_11e00_3 << 8 ^ tmp_11f00_11;
                }
            }
            {
                tmp_11f80_13 = stack_m72;
                uint8_t tmp_11e00_5 = *(uint8_t*)tmp_11f80_13;
                tmp_11f00_11 = stack_m76;
                stack_m76 = (uint32_t)tmp_11e00_5 ^ tmp_11f00_11;
                tmp_11f00_11 = stack_m76;
                stack_m76 = (uint32_t)((uint64_t)(int32_t)tmp_11f00_11 * 0xffffffffcc9e2d51U);
                tmp_11f00_11 = stack_m76;
                uint32_t RAX_41 = sym__rotl32((uint32_t)tmp_11f00_11, 15);
                stack_m76 = (uint32_t)RAX_41;
                tmp_11f00_11 = stack_m76;
                stack_m76 = (uint32_t)((uint64_t)(int32_t)tmp_11f00_11 * 0x1b873593);
                tmp_11f00_11 = stack_m76;
                tmp_11f00_10 = stack_m32;
                stack_m32 = tmp_11f00_11 ^ tmp_11f00_10;
            }
            {
L3: ;
                tmp_11f80_1 = stack_m24;
                tmp_11f00_10 = stack_m32;
                stack_m32 = (uint32_t)tmp_11f80_1 ^ tmp_11f00_10;
                tmp_11f00_10 = stack_m32;
                tmp_11f00_10 = stack_m32;
                stack_m32 = tmp_11f00_10 >> 16 ^ tmp_11f00_10;
                tmp_11f00_10 = stack_m32;
                stack_m32 = (uint32_t)((uint64_t)(int32_t)tmp_11f00_10 * 0xffffffff85ebca6bU);
                tmp_11f00_10 = stack_m32;
                tmp_11f00_10 = stack_m32;
                stack_m32 = tmp_11f00_10 >> 13 ^ tmp_11f00_10;
                tmp_11f00_10 = stack_m32;
                stack_m32 = (uint32_t)((uint64_t)(int32_t)tmp_11f00_10 * 0xffffffffc2b2ae35U);
                tmp_11f00_10 = stack_m32;
                tmp_11f00_10 = stack_m32;
                stack_m32 = tmp_11f00_10 >> 16 ^ tmp_11f00_10;
                tmp_11f00_10 = stack_m32;
                return tmp_11f00_10;
            }
        }
    }
}

