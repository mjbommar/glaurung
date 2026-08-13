#include <stdint.h>

/* Scale stress: raw function size.
 *
 * `big151_branch_ladder` is one function built from a 211-arm descending
 * threshold ladder; every arm carries its own inner branching, which is
 * about a thousand basic blocks at -O0 and still 220-370 after the
 * optimiser has folded what it can. The dispatch value is reduced modulo
 * the arm count, so every input reaches an arm and the differential
 * exercises the ladder rather than the default.
 *
 * `big151_flat_cascade` is the unnested counterpart: 200 independent
 * if/else diamonds in a straight line, all of which execute on every call.
 * A decompiler that gives up on function size, or that collapses repeated
 * arm shapes into one, changes the answer.
 *
 * Generated body; the constants are the deterministic sequences documented
 * beside each loop below. Runtime is a few hundred cheap operations. */

#define BIG151_ARMS 211
#define BIG151_SLOTS 16
#define BIG151_CASCADE_SEED 0x5BF03635u

/* Arm i uses multiplier 1103515245 + 4*i (always odd), addend i*2654435761,
 * probe bit 1 << (i % 24), and the two folding constants i*40503 and
 * i*2246822519 truncated to 16 bits. The arm BODIES cycle through eight
 * different shapes (two-way, three-way, nested, counted loop, while loop,
 * rotate-and-test, arm-rewriting, fold-and-test) so the ladder cannot be
 * folded into a table of per-arm constants -- with uniform bodies gcc -O2
 * collapses all 211 arms into nine basic blocks and the fixture stops
 * measuring anything. */
__attribute__((noinline)) int32_t
big151_branch_ladder(int32_t key, int32_t *sink, int32_t slots) {
    uint32_t acc = 0x9E3779B9u;
    uint32_t tag;
    int32_t arm;
    int32_t index;

    if (sink == 0 || slots < 1 || slots > BIG151_SLOTS) {
        return -1;
    }
    for (index = 0; index < slots; ++index) {
        sink[index] = 0;
    }
    tag = (uint32_t)key % (uint32_t)BIG151_ARMS;

    if (tag >= 210u) {
        arm = 210;
        acc = (acc << 25u) | (acc >> 7u);
        if ((acc % 7u) == 0u) { acc += 0xC981D332u; }
        else { acc = acc * 1103516085u; }
    } else if (tag >= 209u) {
        arm = 209;
        acc ^= 0x2B4A5981u;
        if (acc > 0x6B4A5981u) { acc = acc * 1103516081u + 1u; }
        else if ((acc & 7u) == 3u) { acc = acc >> 7u; }
        else { acc = ~acc + 0x2AE7u; }
    } else if (tag >= 208u) {
        arm = 208;
        acc = acc * 1103516077u + 0x8D12DFD0u;
        if ((acc & 0x00010000u) != 0u) { acc ^= 0x8CB0u; }
        else { acc += 0x80B0u; }
    } else if (tag >= 207u) {
        arm = 207;
        acc = acc * 1103516073u + 0xEEDB661Fu;
        acc ^= acc >> 13u;
        if (acc < 0xEEDB661Fu) { acc += 0xB639u; }
    } else if (tag >= 206u) {
        arm = 206;
        acc ^= 0x50A3EC6Eu;
        while ((acc & 3u) != 0u && arm < 210) {
            acc = acc * 1103516069u + 1u;
            arm += 1;
        }
    } else if (tag >= 205u) {
        arm = 205;
        acc += 0xB26C72BDu;
        if ((acc & 0x00002000u) != 0u) { arm = 505; acc ^= 0xB20Bu; }
    } else if (tag >= 204u) {
        arm = 204;
        for (index = 0; index < 2; ++index) {
            acc = acc * 1103516061u + (uint32_t)index + 0x13D4u;
        }
    } else if (tag >= 203u) {
        arm = 203;
        if ((tag & 1u) != 0u) {
            if ((acc & 0x00000800u) != 0u) { acc = acc * 1103516057u + 0x759Du; }
            else { acc ^= 0x75FD7F5Bu; }
        } else {
            acc += 0x8C5Du;
        }
    } else if (tag >= 202u) {
        arm = 202;
        acc = (acc << 17u) | (acc >> 15u);
        if ((acc % 7u) == 6u) { acc += 0xD7C605AAu; }
        else { acc = acc * 1103516053u; }
    } else if (tag >= 201u) {
        arm = 201;
        acc ^= 0x398E8BF9u;
        if (acc > 0x798E8BF9u) { acc = acc * 1103516049u + 1u; }
        else if ((acc & 7u) == 3u) { acc = acc >> 6u; }
        else { acc = ~acc + 0x392Fu; }
    } else if (tag >= 200u) {
        arm = 200;
        acc = acc * 1103516045u + 0x9B571248u;
        if ((acc & 0x00000100u) != 0u) { acc ^= 0x9AF8u; }
        else { acc += 0x2CF8u; }
    } else if (tag >= 199u) {
        arm = 199;
        acc = acc * 1103516041u + 0xFD1F9897u;
        acc ^= acc >> 5u;
        if (acc < 0xFD1F9897u) { acc += 0x6281u; }
    } else if (tag >= 198u) {
        arm = 198;
        acc ^= 0x5EE81EE6u;
        while ((acc & 3u) != 0u && arm < 202) {
            acc = acc * 1103516037u + 1u;
            arm += 1;
        }
    } else if (tag >= 197u) {
        arm = 197;
        acc += 0xC0B0A535u;
        if ((acc & 0x00000020u) != 0u) { arm = 497; acc ^= 0xC053u; }
    } else if (tag >= 196u) {
        arm = 196;
        for (index = 0; index < 3; ++index) {
            acc = acc * 1103516029u + (uint32_t)index + 0x221Cu;
        }
    } else if (tag >= 195u) {
        arm = 195;
        if ((tag & 1u) != 0u) {
            if ((acc & 0x00000008u) != 0u) { acc = acc * 1103516025u + 0x83E5u; }
            else { acc ^= 0x8441B1D3u; }
        } else {
            acc += 0x38A5u;
        }
    } else if (tag >= 194u) {
        arm = 194;
        acc = (acc << 9u) | (acc >> 23u);
        if ((acc % 7u) == 5u) { acc += 0xE60A3822u; }
        else { acc = acc * 1103516021u; }
    } else if (tag >= 193u) {
        arm = 193;
        acc ^= 0x47D2BE71u;
        if (acc > 0x47D2BE71u) { acc = acc * 1103516017u + 1u; }
        else if ((acc & 7u) == 3u) { acc = acc >> 5u; }
        else { acc = ~acc + 0x4777u; }
    } else if (tag >= 192u) {
        arm = 192;
        acc = acc * 1103516013u + 0xA99B44C0u;
        if ((acc & 0x00000001u) != 0u) { acc ^= 0xA940u; }
        else { acc += 0xD940u; }
    } else if (tag >= 191u) {
        arm = 191;
        acc = acc * 1103516009u + 0x0B63CB0Fu;
        acc ^= acc >> 12u;
        if (acc < 0x0B63CB0Fu) { acc += 0x0EC9u; }
    } else if (tag >= 190u) {
        arm = 190;
        acc ^= 0x6D2C515Eu;
        while ((acc & 3u) != 0u && arm < 194) {
            acc = acc * 1103516005u + 1u;
            arm += 1;
        }
    } else if (tag >= 189u) {
        arm = 189;
        acc += 0xCEF4D7ADu;
        if ((acc & 0x00200000u) != 0u) { arm = 489; acc ^= 0xCE9Bu; }
    } else if (tag >= 188u) {
        arm = 188;
        for (index = 0; index < 4; ++index) {
            acc = acc * 1103515997u + (uint32_t)index + 0x3064u;
        }
    } else if (tag >= 187u) {
        arm = 187;
        if ((tag & 1u) != 0u) {
            if ((acc & 0x00080000u) != 0u) { acc = acc * 1103515993u + 0x922Du; }
            else { acc ^= 0x9285E44Bu; }
        } else {
            acc += 0xE4EDu;
        }
    } else if (tag >= 186u) {
        arm = 186;
        acc = (acc << 1u) | (acc >> 31u);
        if ((acc % 7u) == 4u) { acc += 0xF44E6A9Au; }
        else { acc = acc * 1103515989u; }
    } else if (tag >= 185u) {
        arm = 185;
        acc ^= 0x5616F0E9u;
        if (acc > 0x5616F0E9u) { acc = acc * 1103515985u + 1u; }
        else if ((acc & 7u) == 3u) { acc = acc >> 4u; }
        else { acc = ~acc + 0x55BFu; }
    } else if (tag >= 184u) {
        arm = 184;
        acc = acc * 1103515981u + 0xB7DF7738u;
        if ((acc & 0x00010000u) != 0u) { acc ^= 0xB788u; }
        else { acc += 0x8588u; }
    } else if (tag >= 183u) {
        arm = 183;
        acc = acc * 1103515977u + 0x19A7FD87u;
        acc ^= acc >> 4u;
        if (acc < 0x19A7FD87u) { acc += 0xBB11u; }
    } else if (tag >= 182u) {
        arm = 182;
        acc ^= 0x7B7083D6u;
        while ((acc & 3u) != 0u && arm < 186) {
            acc = acc * 1103515973u + 1u;
            arm += 1;
        }
    } else if (tag >= 181u) {
        arm = 181;
        acc += 0xDD390A25u;
        if ((acc & 0x00002000u) != 0u) { arm = 481; acc ^= 0xDCE3u; }
    } else if (tag >= 180u) {
        arm = 180;
        for (index = 0; index < 2; ++index) {
            acc = acc * 1103515965u + (uint32_t)index + 0x3EACu;
        }
    } else if (tag >= 179u) {
        arm = 179;
        if ((tag & 1u) != 0u) {
            if ((acc & 0x00000800u) != 0u) { acc = acc * 1103515961u + 0xA075u; }
            else { acc ^= 0xA0CA16C3u; }
        } else {
            acc += 0x9135u;
        }
    } else if (tag >= 178u) {
        arm = 178;
        acc = (acc << 24u) | (acc >> 8u);
        if ((acc % 7u) == 3u) { acc += 0x02929D12u; }
        else { acc = acc * 1103515957u; }
    } else if (tag >= 177u) {
        arm = 177;
        acc ^= 0x645B2361u;
        if (acc > 0x645B2361u) { acc = acc * 1103515953u + 1u; }
        else if ((acc & 7u) == 3u) { acc = acc >> 3u; }
        else { acc = ~acc + 0x6407u; }
    } else if (tag >= 176u) {
        arm = 176;
        acc = acc * 1103515949u + 0xC623A9B0u;
        if ((acc & 0x00000100u) != 0u) { acc ^= 0xC5D0u; }
        else { acc += 0x31D0u; }
    } else if (tag >= 175u) {
        arm = 175;
        acc = acc * 1103515945u + 0x27EC2FFFu;
        acc ^= acc >> 11u;
        if (acc < 0x27ED2FFFu) { acc += 0x6759u; }
    } else if (tag >= 174u) {
        arm = 174;
        acc ^= 0x89B4B64Eu;
        while ((acc & 3u) != 0u && arm < 178) {
            acc = acc * 1103515941u + 1u;
            arm += 1;
        }
    } else if (tag >= 173u) {
        arm = 173;
        acc += 0xEB7D3C9Du;
        if ((acc & 0x00000020u) != 0u) { arm = 473; acc ^= 0xEB2Bu; }
    } else if (tag >= 172u) {
        arm = 172;
        for (index = 0; index < 3; ++index) {
            acc = acc * 1103515933u + (uint32_t)index + 0x4CF4u;
        }
    } else if (tag >= 171u) {
        arm = 171;
        if ((tag & 1u) != 0u) {
            if ((acc & 0x00000008u) != 0u) { acc = acc * 1103515929u + 0xAEBDu; }
            else { acc ^= 0xAF0E493Bu; }
        } else {
            acc += 0x3D7Du;
        }
    } else if (tag >= 170u) {
        arm = 170;
        acc = (acc << 16u) | (acc >> 16u);
        if ((acc % 7u) == 2u) { acc += 0x10D6CF8Au; }
        else { acc = acc * 1103515925u; }
    } else if (tag >= 169u) {
        arm = 169;
        acc ^= 0x729F55D9u;
        if (acc > 0x729F55D9u) { acc = acc * 1103515921u + 1u; }
        else if ((acc & 7u) == 3u) { acc = acc >> 2u; }
        else { acc = ~acc + 0x724Fu; }
    } else if (tag >= 168u) {
        arm = 168;
        acc = acc * 1103515917u + 0xD467DC28u;
        if ((acc & 0x00000001u) != 0u) { acc ^= 0xD418u; }
        else { acc += 0xDE18u; }
    } else if (tag >= 167u) {
        arm = 167;
        acc = acc * 1103515913u + 0x36306277u;
        acc ^= acc >> 3u;
        if (acc < 0x36316277u) { acc += 0x13A1u; }
    } else if (tag >= 166u) {
        arm = 166;
        acc ^= 0x97F8E8C6u;
        while ((acc & 3u) != 0u && arm < 170) {
            acc = acc * 1103515909u + 1u;
            arm += 1;
        }
    } else if (tag >= 165u) {
        arm = 165;
        acc += 0xF9C16F15u;
        if ((acc & 0x00200000u) != 0u) { arm = 465; acc ^= 0xF973u; }
    } else if (tag >= 164u) {
        arm = 164;
        for (index = 0; index < 4; ++index) {
            acc = acc * 1103515901u + (uint32_t)index + 0x5B3Cu;
        }
    } else if (tag >= 163u) {
        arm = 163;
        if ((tag & 1u) != 0u) {
            if ((acc & 0x00080000u) != 0u) { acc = acc * 1103515897u + 0xBD05u; }
            else { acc ^= 0xBD527BB3u; }
        } else {
            acc += 0xE9C5u;
        }
    } else if (tag >= 162u) {
        arm = 162;
        acc = (acc << 8u) | (acc >> 24u);
        if ((acc % 7u) == 1u) { acc += 0x1F1B0202u; }
        else { acc = acc * 1103515893u; }
    } else if (tag >= 161u) {
        arm = 161;
        acc ^= 0x80E38851u;
        if (acc > 0xC0E38851u) { acc = acc * 1103515889u + 1u; }
        else if ((acc & 7u) == 3u) { acc = acc >> 1u; }
        else { acc = ~acc + 0x8097u; }
    } else if (tag >= 160u) {
        arm = 160;
        acc = acc * 1103515885u + 0xE2AC0EA0u;
        if ((acc & 0x00010000u) != 0u) { acc ^= 0xE260u; }
        else { acc += 0x8A60u; }
    } else if (tag >= 159u) {
        arm = 159;
        acc = acc * 1103515881u + 0x447494EFu;
        acc ^= acc >> 10u;
        if (acc < 0x447594EFu) { acc += 0xBFE9u; }
    } else if (tag >= 158u) {
        arm = 158;
        acc ^= 0xA63D1B3Eu;
        while ((acc & 3u) != 0u && arm < 162) {
            acc = acc * 1103515877u + 1u;
            arm += 1;
        }
    } else if (tag >= 157u) {
        arm = 157;
        acc += 0x0805A18Du;
        if ((acc & 0x00002000u) != 0u) { arm = 457; acc ^= 0x07BBu; }
    } else if (tag >= 156u) {
        arm = 156;
        for (index = 0; index < 2; ++index) {
            acc = acc * 1103515869u + (uint32_t)index + 0x6984u;
        }
    } else if (tag >= 155u) {
        arm = 155;
        if ((tag & 1u) != 0u) {
            if ((acc & 0x00000800u) != 0u) { acc = acc * 1103515865u + 0xCB4Du; }
            else { acc ^= 0xCB96AE2Bu; }
        } else {
            acc += 0x960Du;
        }
    } else if (tag >= 154u) {
        arm = 154;
        acc = (acc << 31u) | (acc >> 1u);
        if ((acc % 7u) == 0u) { acc += 0x2D5F347Au; }
        else { acc = acc * 1103515861u; }
    } else if (tag >= 153u) {
        arm = 153;
        acc ^= 0x8F27BAC9u;
        if (acc > 0xCF27BAC9u) { acc = acc * 1103515857u + 1u; }
        else if ((acc & 7u) == 3u) { acc = acc >> 7u; }
        else { acc = ~acc + 0x8EDFu; }
    } else if (tag >= 152u) {
        arm = 152;
        acc = acc * 1103515853u + 0xF0F04118u;
        if ((acc & 0x00000100u) != 0u) { acc ^= 0xF0A8u; }
        else { acc += 0x36A8u; }
    } else if (tag >= 151u) {
        arm = 151;
        acc = acc * 1103515849u + 0x52B8C767u;
        acc ^= acc >> 2u;
        if (acc < 0x52B9C767u) { acc += 0x6C31u; }
    } else if (tag >= 150u) {
        arm = 150;
        acc ^= 0xB4814DB6u;
        while ((acc & 3u) != 0u && arm < 154) {
            acc = acc * 1103515845u + 1u;
            arm += 1;
        }
    } else if (tag >= 149u) {
        arm = 149;
        acc += 0x1649D405u;
        if ((acc & 0x00000020u) != 0u) { arm = 449; acc ^= 0x1603u; }
    } else if (tag >= 148u) {
        arm = 148;
        for (index = 0; index < 3; ++index) {
            acc = acc * 1103515837u + (uint32_t)index + 0x77CCu;
        }
    } else if (tag >= 147u) {
        arm = 147;
        if ((tag & 1u) != 0u) {
            if ((acc & 0x00000008u) != 0u) { acc = acc * 1103515833u + 0xD995u; }
            else { acc ^= 0xD9DAE0A3u; }
        } else {
            acc += 0x4255u;
        }
    } else if (tag >= 146u) {
        arm = 146;
        acc = (acc << 23u) | (acc >> 9u);
        if ((acc % 7u) == 6u) { acc += 0x3BA366F2u; }
        else { acc = acc * 1103515829u; }
    } else if (tag >= 145u) {
        arm = 145;
        acc ^= 0x9D6BED41u;
        if (acc > 0xDD6BED41u) { acc = acc * 1103515825u + 1u; }
        else if ((acc & 7u) == 3u) { acc = acc >> 6u; }
        else { acc = ~acc + 0x9D27u; }
    } else if (tag >= 144u) {
        arm = 144;
        acc = acc * 1103515821u + 0xFF347390u;
        if ((acc & 0x00000001u) != 0u) { acc ^= 0xFEF0u; }
        else { acc += 0xE2F0u; }
    } else if (tag >= 143u) {
        arm = 143;
        acc = acc * 1103515817u + 0x60FCF9DFu;
        acc ^= acc >> 9u;
        if (acc < 0x60FDF9DFu) { acc += 0x1879u; }
    } else if (tag >= 142u) {
        arm = 142;
        acc ^= 0xC2C5802Eu;
        while ((acc & 3u) != 0u && arm < 146) {
            acc = acc * 1103515813u + 1u;
            arm += 1;
        }
    } else if (tag >= 141u) {
        arm = 141;
        acc += 0x248E067Du;
        if ((acc & 0x00200000u) != 0u) { arm = 441; acc ^= 0x244Bu; }
    } else if (tag >= 140u) {
        arm = 140;
        for (index = 0; index < 4; ++index) {
            acc = acc * 1103515805u + (uint32_t)index + 0x8614u;
        }
    } else if (tag >= 139u) {
        arm = 139;
        if ((tag & 1u) != 0u) {
            if ((acc & 0x00080000u) != 0u) { acc = acc * 1103515801u + 0xE7DDu; }
            else { acc ^= 0xE81F131Bu; }
        } else {
            acc += 0xEE9Du;
        }
    } else if (tag >= 138u) {
        arm = 138;
        acc = (acc << 15u) | (acc >> 17u);
        if ((acc % 7u) == 5u) { acc += 0x49E7996Au; }
        else { acc = acc * 1103515797u; }
    } else if (tag >= 137u) {
        arm = 137;
        acc ^= 0xABB01FB9u;
        if (acc > 0xEBB01FB9u) { acc = acc * 1103515793u + 1u; }
        else if ((acc & 7u) == 3u) { acc = acc >> 5u; }
        else { acc = ~acc + 0xAB6Fu; }
    } else if (tag >= 136u) {
        arm = 136;
        acc = acc * 1103515789u + 0x0D78A608u;
        if ((acc & 0x00010000u) != 0u) { acc ^= 0x0D38u; }
        else { acc += 0x8F38u; }
    } else if (tag >= 135u) {
        arm = 135;
        acc = acc * 1103515785u + 0x6F412C57u;
        acc ^= acc >> 1u;
        if (acc < 0x6F412C57u) { acc += 0xC4C1u; }
    } else if (tag >= 134u) {
        arm = 134;
        acc ^= 0xD109B2A6u;
        while ((acc & 3u) != 0u && arm < 138) {
            acc = acc * 1103515781u + 1u;
            arm += 1;
        }
    } else if (tag >= 133u) {
        arm = 133;
        acc += 0x32D238F5u;
        if ((acc & 0x00002000u) != 0u) { arm = 433; acc ^= 0x3293u; }
    } else if (tag >= 132u) {
        arm = 132;
        for (index = 0; index < 2; ++index) {
            acc = acc * 1103515773u + (uint32_t)index + 0x945Cu;
        }
    } else if (tag >= 131u) {
        arm = 131;
        if ((tag & 1u) != 0u) {
            if ((acc & 0x00000800u) != 0u) { acc = acc * 1103515769u + 0xF625u; }
            else { acc ^= 0xF6634593u; }
        } else {
            acc += 0x9AE5u;
        }
    } else if (tag >= 130u) {
        arm = 130;
        acc = (acc << 7u) | (acc >> 25u);
        if ((acc % 7u) == 4u) { acc += 0x582BCBE2u; }
        else { acc = acc * 1103515765u; }
    } else if (tag >= 129u) {
        arm = 129;
        acc ^= 0xB9F45231u;
        if (acc > 0xF9F45231u) { acc = acc * 1103515761u + 1u; }
        else if ((acc & 7u) == 3u) { acc = acc >> 4u; }
        else { acc = ~acc + 0xB9B7u; }
    } else if (tag >= 128u) {
        arm = 128;
        acc = acc * 1103515757u + 0x1BBCD880u;
        if ((acc & 0x00000100u) != 0u) { acc ^= 0x1B80u; }
        else { acc += 0x3B80u; }
    } else if (tag >= 127u) {
        arm = 127;
        acc = acc * 1103515753u + 0x7D855ECFu;
        acc ^= acc >> 8u;
        if (acc < 0x7D855ECFu) { acc += 0x7109u; }
    } else if (tag >= 126u) {
        arm = 126;
        acc ^= 0xDF4DE51Eu;
        while ((acc & 3u) != 0u && arm < 130) {
            acc = acc * 1103515749u + 1u;
            arm += 1;
        }
    } else if (tag >= 125u) {
        arm = 125;
        acc += 0x41166B6Du;
        if ((acc & 0x00000020u) != 0u) { arm = 425; acc ^= 0x40DBu; }
    } else if (tag >= 124u) {
        arm = 124;
        for (index = 0; index < 3; ++index) {
            acc = acc * 1103515741u + (uint32_t)index + 0xA2A4u;
        }
    } else if (tag >= 123u) {
        arm = 123;
        if ((tag & 1u) != 0u) {
            if ((acc & 0x00000008u) != 0u) { acc = acc * 1103515737u + 0x046Du; }
            else { acc ^= 0x04A7780Bu; }
        } else {
            acc += 0x472Du;
        }
    } else if (tag >= 122u) {
        arm = 122;
        acc = (acc << 30u) | (acc >> 2u);
        if ((acc % 7u) == 3u) { acc += 0x666FFE5Au; }
        else { acc = acc * 1103515733u; }
    } else if (tag >= 121u) {
        arm = 121;
        acc ^= 0xC83884A9u;
        if (acc > 0xC83884A9u) { acc = acc * 1103515729u + 1u; }
        else if ((acc & 7u) == 3u) { acc = acc >> 3u; }
        else { acc = ~acc + 0xC7FFu; }
    } else if (tag >= 120u) {
        arm = 120;
        acc = acc * 1103515725u + 0x2A010AF8u;
        if ((acc & 0x00000001u) != 0u) { acc ^= 0x29C8u; }
        else { acc += 0xE7C8u; }
    } else if (tag >= 119u) {
        arm = 119;
        acc = acc * 1103515721u + 0x8BC99147u;
        acc ^= acc >> 15u;
        if (acc < 0x8BC99147u) { acc += 0x1D51u; }
    } else if (tag >= 118u) {
        arm = 118;
        acc ^= 0xED921796u;
        while ((acc & 3u) != 0u && arm < 122) {
            acc = acc * 1103515717u + 1u;
            arm += 1;
        }
    } else if (tag >= 117u) {
        arm = 117;
        acc += 0x4F5A9DE5u;
        if ((acc & 0x00200000u) != 0u) { arm = 417; acc ^= 0x4F23u; }
    } else if (tag >= 116u) {
        arm = 116;
        for (index = 0; index < 4; ++index) {
            acc = acc * 1103515709u + (uint32_t)index + 0xB0ECu;
        }
    } else if (tag >= 115u) {
        arm = 115;
        if ((tag & 1u) != 0u) {
            if ((acc & 0x00080000u) != 0u) { acc = acc * 1103515705u + 0x12B5u; }
            else { acc ^= 0x12EBAA83u; }
        } else {
            acc += 0xF375u;
        }
    } else if (tag >= 114u) {
        arm = 114;
        acc = (acc << 22u) | (acc >> 10u);
        if ((acc % 7u) == 2u) { acc += 0x74B430D2u; }
        else { acc = acc * 1103515701u; }
    } else if (tag >= 113u) {
        arm = 113;
        acc ^= 0xD67CB721u;
        if (acc > 0xD67CB721u) { acc = acc * 1103515697u + 1u; }
        else if ((acc & 7u) == 3u) { acc = acc >> 2u; }
        else { acc = ~acc + 0xD647u; }
    } else if (tag >= 112u) {
        arm = 112;
        acc = acc * 1103515693u + 0x38453D70u;
        if ((acc & 0x00010000u) != 0u) { acc ^= 0x3810u; }
        else { acc += 0x9410u; }
    } else if (tag >= 111u) {
        arm = 111;
        acc = acc * 1103515689u + 0x9A0DC3BFu;
        acc ^= acc >> 7u;
        if (acc < 0x9A0DC3BFu) { acc += 0xC999u; }
    } else if (tag >= 110u) {
        arm = 110;
        acc ^= 0xFBD64A0Eu;
        while ((acc & 3u) != 0u && arm < 114) {
            acc = acc * 1103515685u + 1u;
            arm += 1;
        }
    } else if (tag >= 109u) {
        arm = 109;
        acc += 0x5D9ED05Du;
        if ((acc & 0x00002000u) != 0u) { arm = 409; acc ^= 0x5D6Bu; }
    } else if (tag >= 108u) {
        arm = 108;
        for (index = 0; index < 2; ++index) {
            acc = acc * 1103515677u + (uint32_t)index + 0xBF34u;
        }
    } else if (tag >= 107u) {
        arm = 107;
        if ((tag & 1u) != 0u) {
            if ((acc & 0x00000800u) != 0u) { acc = acc * 1103515673u + 0x20FDu; }
            else { acc ^= 0x212FDCFBu; }
        } else {
            acc += 0x9FBDu;
        }
    } else if (tag >= 106u) {
        arm = 106;
        acc = (acc << 14u) | (acc >> 18u);
        if ((acc % 7u) == 1u) { acc += 0x82F8634Au; }
        else { acc = acc * 1103515669u; }
    } else if (tag >= 105u) {
        arm = 105;
        acc ^= 0xE4C0E999u;
        if (acc > 0xE4C0E999u) { acc = acc * 1103515665u + 1u; }
        else if ((acc & 7u) == 3u) { acc = acc >> 1u; }
        else { acc = ~acc + 0xE48Fu; }
    } else if (tag >= 104u) {
        arm = 104;
        acc = acc * 1103515661u + 0x46896FE8u;
        if ((acc & 0x00000100u) != 0u) { acc ^= 0x4658u; }
        else { acc += 0x4058u; }
    } else if (tag >= 103u) {
        arm = 103;
        acc = acc * 1103515657u + 0xA851F637u;
        acc ^= acc >> 14u;
        if (acc < 0xA851F637u) { acc += 0x75E1u; }
    } else if (tag >= 102u) {
        arm = 102;
        acc ^= 0x0A1A7C86u;
        while ((acc & 3u) != 0u && arm < 106) {
            acc = acc * 1103515653u + 1u;
            arm += 1;
        }
    } else if (tag >= 101u) {
        arm = 101;
        acc += 0x6BE302D5u;
        if ((acc & 0x00000020u) != 0u) { arm = 401; acc ^= 0x6BB3u; }
    } else if (tag >= 100u) {
        arm = 100;
        for (index = 0; index < 3; ++index) {
            acc = acc * 1103515645u + (uint32_t)index + 0xCD7Cu;
        }
    } else if (tag >= 99u) {
        arm = 99;
        if ((tag & 1u) != 0u) {
            if ((acc & 0x00000008u) != 0u) { acc = acc * 1103515641u + 0x2F45u; }
            else { acc ^= 0x2F740F73u; }
        } else {
            acc += 0x4C05u;
        }
    } else if (tag >= 98u) {
        arm = 98;
        acc = (acc << 6u) | (acc >> 26u);
        if ((acc % 7u) == 0u) { acc += 0x913C95C2u; }
        else { acc = acc * 1103515637u; }
    } else if (tag >= 97u) {
        arm = 97;
        acc ^= 0xF3051C11u;
        if (acc > 0xF3051C11u) { acc = acc * 1103515633u + 1u; }
        else if ((acc & 7u) == 3u) { acc = acc >> 7u; }
        else { acc = ~acc + 0xF2D7u; }
    } else if (tag >= 96u) {
        arm = 96;
        acc = acc * 1103515629u + 0x54CDA260u;
        if ((acc & 0x00000001u) != 0u) { acc ^= 0x54A0u; }
        else { acc += 0xECA0u; }
    } else if (tag >= 95u) {
        arm = 95;
        acc = acc * 1103515625u + 0xB69628AFu;
        acc ^= acc >> 6u;
        if (acc < 0xB69728AFu) { acc += 0x2229u; }
    } else if (tag >= 94u) {
        arm = 94;
        acc ^= 0x185EAEFEu;
        while ((acc & 3u) != 0u && arm < 98) {
            acc = acc * 1103515621u + 1u;
            arm += 1;
        }
    } else if (tag >= 93u) {
        arm = 93;
        acc += 0x7A27354Du;
        if ((acc & 0x00200000u) != 0u) { arm = 393; acc ^= 0x79FBu; }
    } else if (tag >= 92u) {
        arm = 92;
        for (index = 0; index < 4; ++index) {
            acc = acc * 1103515613u + (uint32_t)index + 0xDBC4u;
        }
    } else if (tag >= 91u) {
        arm = 91;
        if ((tag & 1u) != 0u) {
            if ((acc & 0x00080000u) != 0u) { acc = acc * 1103515609u + 0x3D8Du; }
            else { acc ^= 0x3DB841EBu; }
        } else {
            acc += 0xF84Du;
        }
    } else if (tag >= 90u) {
        arm = 90;
        acc = (acc << 29u) | (acc >> 3u);
        if ((acc % 7u) == 6u) { acc += 0x9F80C83Au; }
        else { acc = acc * 1103515605u; }
    } else if (tag >= 89u) {
        arm = 89;
        acc ^= 0x01494E89u;
        if (acc > 0x41494E89u) { acc = acc * 1103515601u + 1u; }
        else if ((acc & 7u) == 3u) { acc = acc >> 6u; }
        else { acc = ~acc + 0x011Fu; }
    } else if (tag >= 88u) {
        arm = 88;
        acc = acc * 1103515597u + 0x6311D4D8u;
        if ((acc & 0x00010000u) != 0u) { acc ^= 0x62E8u; }
        else { acc += 0x98E8u; }
    } else if (tag >= 87u) {
        arm = 87;
        acc = acc * 1103515593u + 0xC4DA5B27u;
        acc ^= acc >> 13u;
        if (acc < 0xC4DB5B27u) { acc += 0xCE71u; }
    } else if (tag >= 86u) {
        arm = 86;
        acc ^= 0x26A2E176u;
        while ((acc & 3u) != 0u && arm < 90) {
            acc = acc * 1103515589u + 1u;
            arm += 1;
        }
    } else if (tag >= 85u) {
        arm = 85;
        acc += 0x886B67C5u;
        if ((acc & 0x00002000u) != 0u) { arm = 385; acc ^= 0x8843u; }
    } else if (tag >= 84u) {
        arm = 84;
        for (index = 0; index < 2; ++index) {
            acc = acc * 1103515581u + (uint32_t)index + 0xEA0Cu;
        }
    } else if (tag >= 83u) {
        arm = 83;
        if ((tag & 1u) != 0u) {
            if ((acc & 0x00000800u) != 0u) { acc = acc * 1103515577u + 0x4BD5u; }
            else { acc ^= 0x4BFC7463u; }
        } else {
            acc += 0xA495u;
        }
    } else if (tag >= 82u) {
        arm = 82;
        acc = (acc << 21u) | (acc >> 11u);
        if ((acc % 7u) == 5u) { acc += 0xADC4FAB2u; }
        else { acc = acc * 1103515573u; }
    } else if (tag >= 81u) {
        arm = 81;
        acc ^= 0x0F8D8101u;
        if (acc > 0x4F8D8101u) { acc = acc * 1103515569u + 1u; }
        else if ((acc & 7u) == 3u) { acc = acc >> 5u; }
        else { acc = ~acc + 0x0F67u; }
    } else if (tag >= 80u) {
        arm = 80;
        acc = acc * 1103515565u + 0x71560750u;
        if ((acc & 0x00000100u) != 0u) { acc ^= 0x7130u; }
        else { acc += 0x4530u; }
    } else if (tag >= 79u) {
        arm = 79;
        acc = acc * 1103515561u + 0xD31E8D9Fu;
        acc ^= acc >> 5u;
        if (acc < 0xD31F8D9Fu) { acc += 0x7AB9u; }
    } else if (tag >= 78u) {
        arm = 78;
        acc ^= 0x34E713EEu;
        while ((acc & 3u) != 0u && arm < 82) {
            acc = acc * 1103515557u + 1u;
            arm += 1;
        }
    } else if (tag >= 77u) {
        arm = 77;
        acc += 0x96AF9A3Du;
        if ((acc & 0x00000020u) != 0u) { arm = 377; acc ^= 0x968Bu; }
    } else if (tag >= 76u) {
        arm = 76;
        for (index = 0; index < 3; ++index) {
            acc = acc * 1103515549u + (uint32_t)index + 0xF854u;
        }
    } else if (tag >= 75u) {
        arm = 75;
        if ((tag & 1u) != 0u) {
            if ((acc & 0x00000008u) != 0u) { acc = acc * 1103515545u + 0x5A1Du; }
            else { acc ^= 0x5A40A6DBu; }
        } else {
            acc += 0x50DDu;
        }
    } else if (tag >= 74u) {
        arm = 74;
        acc = (acc << 13u) | (acc >> 19u);
        if ((acc % 7u) == 4u) { acc += 0xBC092D2Au; }
        else { acc = acc * 1103515541u; }
    } else if (tag >= 73u) {
        arm = 73;
        acc ^= 0x1DD1B379u;
        if (acc > 0x5DD1B379u) { acc = acc * 1103515537u + 1u; }
        else if ((acc & 7u) == 3u) { acc = acc >> 4u; }
        else { acc = ~acc + 0x1DAFu; }
    } else if (tag >= 72u) {
        arm = 72;
        acc = acc * 1103515533u + 0x7F9A39C8u;
        if ((acc & 0x00000001u) != 0u) { acc ^= 0x7F78u; }
        else { acc += 0xF178u; }
    } else if (tag >= 71u) {
        arm = 71;
        acc = acc * 1103515529u + 0xE162C017u;
        acc ^= acc >> 12u;
        if (acc < 0xE163C017u) { acc += 0x2701u; }
    } else if (tag >= 70u) {
        arm = 70;
        acc ^= 0x432B4666u;
        while ((acc & 3u) != 0u && arm < 74) {
            acc = acc * 1103515525u + 1u;
            arm += 1;
        }
    } else if (tag >= 69u) {
        arm = 69;
        acc += 0xA4F3CCB5u;
        if ((acc & 0x00200000u) != 0u) { arm = 369; acc ^= 0xA4D3u; }
    } else if (tag >= 68u) {
        arm = 68;
        for (index = 0; index < 4; ++index) {
            acc = acc * 1103515517u + (uint32_t)index + 0x069Cu;
        }
    } else if (tag >= 67u) {
        arm = 67;
        if ((tag & 1u) != 0u) {
            if ((acc & 0x00080000u) != 0u) { acc = acc * 1103515513u + 0x6865u; }
            else { acc ^= 0x6884D953u; }
        } else {
            acc += 0xFD25u;
        }
    } else if (tag >= 66u) {
        arm = 66;
        acc = (acc << 5u) | (acc >> 27u);
        if ((acc % 7u) == 3u) { acc += 0xCA4D5FA2u; }
        else { acc = acc * 1103515509u; }
    } else if (tag >= 65u) {
        arm = 65;
        acc ^= 0x2C15E5F1u;
        if (acc > 0x6C15E5F1u) { acc = acc * 1103515505u + 1u; }
        else if ((acc & 7u) == 3u) { acc = acc >> 3u; }
        else { acc = ~acc + 0x2BF7u; }
    } else if (tag >= 64u) {
        arm = 64;
        acc = acc * 1103515501u + 0x8DDE6C40u;
        if ((acc & 0x00010000u) != 0u) { acc ^= 0x8DC0u; }
        else { acc += 0x9DC0u; }
    } else if (tag >= 63u) {
        arm = 63;
        acc = acc * 1103515497u + 0xEFA6F28Fu;
        acc ^= acc >> 4u;
        if (acc < 0xEFA7F28Fu) { acc += 0xD349u; }
    } else if (tag >= 62u) {
        arm = 62;
        acc ^= 0x516F78DEu;
        while ((acc & 3u) != 0u && arm < 66) {
            acc = acc * 1103515493u + 1u;
            arm += 1;
        }
    } else if (tag >= 61u) {
        arm = 61;
        acc += 0xB337FF2Du;
        if ((acc & 0x00002000u) != 0u) { arm = 361; acc ^= 0xB31Bu; }
    } else if (tag >= 60u) {
        arm = 60;
        for (index = 0; index < 2; ++index) {
            acc = acc * 1103515485u + (uint32_t)index + 0x14E4u;
        }
    } else if (tag >= 59u) {
        arm = 59;
        if ((tag & 1u) != 0u) {
            if ((acc & 0x00000800u) != 0u) { acc = acc * 1103515481u + 0x76ADu; }
            else { acc ^= 0x76C90BCBu; }
        } else {
            acc += 0xA96Du;
        }
    } else if (tag >= 58u) {
        arm = 58;
        acc = (acc << 28u) | (acc >> 4u);
        if ((acc % 7u) == 2u) { acc += 0xD891921Au; }
        else { acc = acc * 1103515477u; }
    } else if (tag >= 57u) {
        arm = 57;
        acc ^= 0x3A5A1869u;
        if (acc > 0x7A5A1869u) { acc = acc * 1103515473u + 1u; }
        else if ((acc & 7u) == 3u) { acc = acc >> 2u; }
        else { acc = ~acc + 0x3A3Fu; }
    } else if (tag >= 56u) {
        arm = 56;
        acc = acc * 1103515469u + 0x9C229EB8u;
        if ((acc & 0x00000100u) != 0u) { acc ^= 0x9C08u; }
        else { acc += 0x4A08u; }
    } else if (tag >= 55u) {
        arm = 55;
        acc = acc * 1103515465u + 0xFDEB2507u;
        acc ^= acc >> 11u;
        if (acc < 0xFDEB2507u) { acc += 0x7F91u; }
    } else if (tag >= 54u) {
        arm = 54;
        acc ^= 0x5FB3AB56u;
        while ((acc & 3u) != 0u && arm < 58) {
            acc = acc * 1103515461u + 1u;
            arm += 1;
        }
    } else if (tag >= 53u) {
        arm = 53;
        acc += 0xC17C31A5u;
        if ((acc & 0x00000020u) != 0u) { arm = 353; acc ^= 0xC163u; }
    } else if (tag >= 52u) {
        arm = 52;
        for (index = 0; index < 3; ++index) {
            acc = acc * 1103515453u + (uint32_t)index + 0x232Cu;
        }
    } else if (tag >= 51u) {
        arm = 51;
        if ((tag & 1u) != 0u) {
            if ((acc & 0x00000008u) != 0u) { acc = acc * 1103515449u + 0x84F5u; }
            else { acc ^= 0x850D3E43u; }
        } else {
            acc += 0x55B5u;
        }
    } else if (tag >= 50u) {
        arm = 50;
        acc = (acc << 20u) | (acc >> 12u);
        if ((acc % 7u) == 1u) { acc += 0xE6D5C492u; }
        else { acc = acc * 1103515445u; }
    } else if (tag >= 49u) {
        arm = 49;
        acc ^= 0x489E4AE1u;
        if (acc > 0x489E4AE1u) { acc = acc * 1103515441u + 1u; }
        else if ((acc & 7u) == 3u) { acc = acc >> 1u; }
        else { acc = ~acc + 0x4887u; }
    } else if (tag >= 48u) {
        arm = 48;
        acc = acc * 1103515437u + 0xAA66D130u;
        if ((acc & 0x00000001u) != 0u) { acc ^= 0xAA50u; }
        else { acc += 0xF650u; }
    } else if (tag >= 47u) {
        arm = 47;
        acc = acc * 1103515433u + 0x0C2F577Fu;
        acc ^= acc >> 3u;
        if (acc < 0x0C2F577Fu) { acc += 0x2BD9u; }
    } else if (tag >= 46u) {
        arm = 46;
        acc ^= 0x6DF7DDCEu;
        while ((acc & 3u) != 0u && arm < 50) {
            acc = acc * 1103515429u + 1u;
            arm += 1;
        }
    } else if (tag >= 45u) {
        arm = 45;
        acc += 0xCFC0641Du;
        if ((acc & 0x00200000u) != 0u) { arm = 345; acc ^= 0xCFABu; }
    } else if (tag >= 44u) {
        arm = 44;
        for (index = 0; index < 4; ++index) {
            acc = acc * 1103515421u + (uint32_t)index + 0x3174u;
        }
    } else if (tag >= 43u) {
        arm = 43;
        if ((tag & 1u) != 0u) {
            if ((acc & 0x00080000u) != 0u) { acc = acc * 1103515417u + 0x933Du; }
            else { acc ^= 0x935170BBu; }
        } else {
            acc += 0x01FDu;
        }
    } else if (tag >= 42u) {
        arm = 42;
        acc = (acc << 12u) | (acc >> 20u);
        if ((acc % 7u) == 0u) { acc += 0xF519F70Au; }
        else { acc = acc * 1103515413u; }
    } else if (tag >= 41u) {
        arm = 41;
        acc ^= 0x56E27D59u;
        if (acc > 0x56E27D59u) { acc = acc * 1103515409u + 1u; }
        else if ((acc & 7u) == 3u) { acc = acc >> 7u; }
        else { acc = ~acc + 0x56CFu; }
    } else if (tag >= 40u) {
        arm = 40;
        acc = acc * 1103515405u + 0xB8AB03A8u;
        if ((acc & 0x00010000u) != 0u) { acc ^= 0xB898u; }
        else { acc += 0xA298u; }
    } else if (tag >= 39u) {
        arm = 39;
        acc = acc * 1103515401u + 0x1A7389F7u;
        acc ^= acc >> 10u;
        if (acc < 0x1A7389F7u) { acc += 0xD821u; }
    } else if (tag >= 38u) {
        arm = 38;
        acc ^= 0x7C3C1046u;
        while ((acc & 3u) != 0u && arm < 42) {
            acc = acc * 1103515397u + 1u;
            arm += 1;
        }
    } else if (tag >= 37u) {
        arm = 37;
        acc += 0xDE049695u;
        if ((acc & 0x00002000u) != 0u) { arm = 337; acc ^= 0xDDF3u; }
    } else if (tag >= 36u) {
        arm = 36;
        for (index = 0; index < 2; ++index) {
            acc = acc * 1103515389u + (uint32_t)index + 0x3FBCu;
        }
    } else if (tag >= 35u) {
        arm = 35;
        if ((tag & 1u) != 0u) {
            if ((acc & 0x00000800u) != 0u) { acc = acc * 1103515385u + 0xA185u; }
            else { acc ^= 0xA195A333u; }
        } else {
            acc += 0xAE45u;
        }
    } else if (tag >= 34u) {
        arm = 34;
        acc = (acc << 4u) | (acc >> 28u);
        if ((acc % 7u) == 6u) { acc += 0x035E2982u; }
        else { acc = acc * 1103515381u; }
    } else if (tag >= 33u) {
        arm = 33;
        acc ^= 0x6526AFD1u;
        if (acc > 0x6526AFD1u) { acc = acc * 1103515377u + 1u; }
        else if ((acc & 7u) == 3u) { acc = acc >> 6u; }
        else { acc = ~acc + 0x6517u; }
    } else if (tag >= 32u) {
        arm = 32;
        acc = acc * 1103515373u + 0xC6EF3620u;
        if ((acc & 0x00000100u) != 0u) { acc ^= 0xC6E0u; }
        else { acc += 0x4EE0u; }
    } else if (tag >= 31u) {
        arm = 31;
        acc = acc * 1103515369u + 0x28B7BC6Fu;
        acc ^= acc >> 2u;
        if (acc < 0x28B7BC6Fu) { acc += 0x8469u; }
    } else if (tag >= 30u) {
        arm = 30;
        acc ^= 0x8A8042BEu;
        while ((acc & 3u) != 0u && arm < 34) {
            acc = acc * 1103515365u + 1u;
            arm += 1;
        }
    } else if (tag >= 29u) {
        arm = 29;
        acc += 0xEC48C90Du;
        if ((acc & 0x00000020u) != 0u) { arm = 329; acc ^= 0xEC3Bu; }
    } else if (tag >= 28u) {
        arm = 28;
        for (index = 0; index < 3; ++index) {
            acc = acc * 1103515357u + (uint32_t)index + 0x4E04u;
        }
    } else if (tag >= 27u) {
        arm = 27;
        if ((tag & 1u) != 0u) {
            if ((acc & 0x00000008u) != 0u) { acc = acc * 1103515353u + 0xAFCDu; }
            else { acc ^= 0xAFD9D5ABu; }
        } else {
            acc += 0x5A8Du;
        }
    } else if (tag >= 26u) {
        arm = 26;
        acc = (acc << 27u) | (acc >> 5u);
        if ((acc % 7u) == 5u) { acc += 0x11A25BFAu; }
        else { acc = acc * 1103515349u; }
    } else if (tag >= 25u) {
        arm = 25;
        acc ^= 0x736AE249u;
        if (acc > 0x736AE249u) { acc = acc * 1103515345u + 1u; }
        else if ((acc & 7u) == 3u) { acc = acc >> 5u; }
        else { acc = ~acc + 0x735Fu; }
    } else if (tag >= 24u) {
        arm = 24;
        acc = acc * 1103515341u + 0xD5336898u;
        if ((acc & 0x00000001u) != 0u) { acc ^= 0xD528u; }
        else { acc += 0xFB28u; }
    } else if (tag >= 23u) {
        arm = 23;
        acc = acc * 1103515337u + 0x36FBEEE7u;
        acc ^= acc >> 9u;
        if (acc < 0x36FBEEE7u) { acc += 0x30B1u; }
    } else if (tag >= 22u) {
        arm = 22;
        acc ^= 0x98C47536u;
        while ((acc & 3u) != 0u && arm < 26) {
            acc = acc * 1103515333u + 1u;
            arm += 1;
        }
    } else if (tag >= 21u) {
        arm = 21;
        acc += 0xFA8CFB85u;
        if ((acc & 0x00200000u) != 0u) { arm = 321; acc ^= 0xFA83u; }
    } else if (tag >= 20u) {
        arm = 20;
        for (index = 0; index < 4; ++index) {
            acc = acc * 1103515325u + (uint32_t)index + 0x5C4Cu;
        }
    } else if (tag >= 19u) {
        arm = 19;
        if ((tag & 1u) != 0u) {
            if ((acc & 0x00080000u) != 0u) { acc = acc * 1103515321u + 0xBE15u; }
            else { acc ^= 0xBE1E0823u; }
        } else {
            acc += 0x06D5u;
        }
    } else if (tag >= 18u) {
        arm = 18;
        acc = (acc << 19u) | (acc >> 13u);
        if ((acc % 7u) == 4u) { acc += 0x1FE68E72u; }
        else { acc = acc * 1103515317u; }
    } else if (tag >= 17u) {
        arm = 17;
        acc ^= 0x81AF14C1u;
        if (acc > 0xC1AF14C1u) { acc = acc * 1103515313u + 1u; }
        else if ((acc & 7u) == 3u) { acc = acc >> 4u; }
        else { acc = ~acc + 0x81A7u; }
    } else if (tag >= 16u) {
        arm = 16;
        acc = acc * 1103515309u + 0xE3779B10u;
        if ((acc & 0x00010000u) != 0u) { acc ^= 0xE370u; }
        else { acc += 0xA770u; }
    } else if (tag >= 15u) {
        arm = 15;
        acc = acc * 1103515305u + 0x4540215Fu;
        acc ^= acc >> 1u;
        if (acc < 0x4541215Fu) { acc += 0xDCF9u; }
    } else if (tag >= 14u) {
        arm = 14;
        acc ^= 0xA708A7AEu;
        while ((acc & 3u) != 0u && arm < 18) {
            acc = acc * 1103515301u + 1u;
            arm += 1;
        }
    } else if (tag >= 13u) {
        arm = 13;
        acc += 0x08D12DFDu;
        if ((acc & 0x00002000u) != 0u) { arm = 313; acc ^= 0x08CBu; }
    } else if (tag >= 12u) {
        arm = 12;
        for (index = 0; index < 2; ++index) {
            acc = acc * 1103515293u + (uint32_t)index + 0x6A94u;
        }
    } else if (tag >= 11u) {
        arm = 11;
        if ((tag & 1u) != 0u) {
            if ((acc & 0x00000800u) != 0u) { acc = acc * 1103515289u + 0xCC5Du; }
            else { acc ^= 0xCC623A9Bu; }
        } else {
            acc += 0xB31Du;
        }
    } else if (tag >= 10u) {
        arm = 10;
        acc = (acc << 11u) | (acc >> 21u);
        if ((acc % 7u) == 3u) { acc += 0x2E2AC0EAu; }
        else { acc = acc * 1103515285u; }
    } else if (tag >= 9u) {
        arm = 9;
        acc ^= 0x8FF34739u;
        if (acc > 0xCFF34739u) { acc = acc * 1103515281u + 1u; }
        else if ((acc & 7u) == 3u) { acc = acc >> 3u; }
        else { acc = ~acc + 0x8FEFu; }
    } else if (tag >= 8u) {
        arm = 8;
        acc = acc * 1103515277u + 0xF1BBCD88u;
        if ((acc & 0x00000100u) != 0u) { acc ^= 0xF1B8u; }
        else { acc += 0x53B8u; }
    } else if (tag >= 7u) {
        arm = 7;
        acc = acc * 1103515273u + 0x538453D7u;
        acc ^= acc >> 8u;
        if (acc < 0x538553D7u) { acc += 0x8941u; }
    } else if (tag >= 6u) {
        arm = 6;
        acc ^= 0xB54CDA26u;
        while ((acc & 3u) != 0u && arm < 10) {
            acc = acc * 1103515269u + 1u;
            arm += 1;
        }
    } else if (tag >= 5u) {
        arm = 5;
        acc += 0x17156075u;
        if ((acc & 0x00000020u) != 0u) { arm = 305; acc ^= 0x1713u; }
    } else if (tag >= 4u) {
        arm = 4;
        for (index = 0; index < 3; ++index) {
            acc = acc * 1103515261u + (uint32_t)index + 0x78DCu;
        }
    } else if (tag >= 3u) {
        arm = 3;
        if ((tag & 1u) != 0u) {
            if ((acc & 0x00000008u) != 0u) { acc = acc * 1103515257u + 0xDAA5u; }
            else { acc ^= 0xDAA66D13u; }
        } else {
            acc += 0x5F65u;
        }
    } else if (tag >= 2u) {
        arm = 2;
        acc = (acc << 3u) | (acc >> 29u);
        if ((acc % 7u) == 2u) { acc += 0x3C6EF362u; }
        else { acc = acc * 1103515253u; }
    } else if (tag >= 1u) {
        arm = 1;
        acc ^= 0x9E3779B1u;
        if (acc > 0xDE3779B1u) { acc = acc * 1103515249u + 1u; }
        else if ((acc & 7u) == 3u) { acc = acc >> 2u; }
        else { acc = ~acc + 0x9E37u; }
    } else {
        arm = 0;
        acc ^= 0xDEADBEEFu;
        if ((acc & 0x00008000u) != 0u) { acc = acc * 3u + 1u; }
        else { acc = acc >> 1; }
    }

    sink[(uint32_t)arm % (uint32_t)slots] = (int32_t)(acc & 0x7FFFFFFFu);
    sink[0] = (int32_t)((uint32_t)sink[0] ^ (uint32_t)arm);
    return (int32_t)(acc & 0x0000FFFFu) + arm;
}

/* Step j probes bit 1 << (j % 32) and folds with multiplier
 * 1103515245 + 8*j (always odd) or the constant j*2654435761. Every step
 * runs on every call, so all 200 diamonds are on the executed path.
 *
 * Both arms are cheap and side-effect free, which is deliberate: at -O0
 * this is 200 real two-way branches, and at -O2 both compilers if-convert
 * the lot into one branchless run of ~1200 instructions. The two lanes
 * therefore stress opposite ends of the same problem -- block count on one
 * side, a single enormous straight-line expression on the other -- and
 * must still agree on the value. */
__attribute__((noinline)) uint32_t big151_flat_cascade(int32_t seed) {
    uint32_t state = (uint32_t)seed ^ BIG151_CASCADE_SEED;

    if ((state & 0x00000001u) != 0u) { state = state * 1103515245u + 0x9E37u; }
    else { state ^= 0x9E3779B1u; }
    if ((state & 0x00000002u) != 0u) { state = state * 1103515253u + 0x3C6Eu; }
    else { state ^= 0x3C6EF362u; }
    if ((state & 0x00000004u) != 0u) { state = state * 1103515261u + 0xDAA5u; }
    else { state ^= 0xDAA66D13u; }
    if ((state & 0x00000008u) != 0u) { state = state * 1103515269u + 0x78DCu; }
    else { state ^= 0x78DDE6C4u; }
    if ((state & 0x00000010u) != 0u) { state = state * 1103515277u + 0x1713u; }
    else { state ^= 0x17156075u; }
    if ((state & 0x00000020u) != 0u) { state = state * 1103515285u + 0xB54Au; }
    else { state ^= 0xB54CDA26u; }
    if ((state & 0x00000040u) != 0u) { state = state * 1103515293u + 0x5381u; }
    else { state ^= 0x538453D7u; }
    if ((state & 0x00000080u) != 0u) { state = state * 1103515301u + 0xF1B8u; }
    else { state ^= 0xF1BBCD88u; }
    if ((state & 0x00000100u) != 0u) { state = state * 1103515309u + 0x8FEFu; }
    else { state ^= 0x8FF34739u; }
    if ((state & 0x00000200u) != 0u) { state = state * 1103515317u + 0x2E26u; }
    else { state ^= 0x2E2AC0EAu; }
    if ((state & 0x00000400u) != 0u) { state = state * 1103515325u + 0xCC5Du; }
    else { state ^= 0xCC623A9Bu; }
    if ((state & 0x00000800u) != 0u) { state = state * 1103515333u + 0x6A94u; }
    else { state ^= 0x6A99B44Cu; }
    if ((state & 0x00001000u) != 0u) { state = state * 1103515341u + 0x08CBu; }
    else { state ^= 0x08D12DFDu; }
    if ((state & 0x00002000u) != 0u) { state = state * 1103515349u + 0xA702u; }
    else { state ^= 0xA708A7AEu; }
    if ((state & 0x00004000u) != 0u) { state = state * 1103515357u + 0x4539u; }
    else { state ^= 0x4540215Fu; }
    if ((state & 0x00008000u) != 0u) { state = state * 1103515365u + 0xE370u; }
    else { state ^= 0xE3779B10u; }
    if ((state & 0x00010000u) != 0u) { state = state * 1103515373u + 0x81A7u; }
    else { state ^= 0x81AF14C1u; }
    if ((state & 0x00020000u) != 0u) { state = state * 1103515381u + 0x1FDEu; }
    else { state ^= 0x1FE68E72u; }
    if ((state & 0x00040000u) != 0u) { state = state * 1103515389u + 0xBE15u; }
    else { state ^= 0xBE1E0823u; }
    if ((state & 0x00080000u) != 0u) { state = state * 1103515397u + 0x5C4Cu; }
    else { state ^= 0x5C5581D4u; }
    if ((state & 0x00100000u) != 0u) { state = state * 1103515405u + 0xFA83u; }
    else { state ^= 0xFA8CFB85u; }
    if ((state & 0x00200000u) != 0u) { state = state * 1103515413u + 0x98BAu; }
    else { state ^= 0x98C47536u; }
    if ((state & 0x00400000u) != 0u) { state = state * 1103515421u + 0x36F1u; }
    else { state ^= 0x36FBEEE7u; }
    if ((state & 0x00800000u) != 0u) { state = state * 1103515429u + 0xD528u; }
    else { state ^= 0xD5336898u; }
    if ((state & 0x01000000u) != 0u) { state = state * 1103515437u + 0x735Fu; }
    else { state ^= 0x736AE249u; }
    if ((state & 0x02000000u) != 0u) { state = state * 1103515445u + 0x1196u; }
    else { state ^= 0x11A25BFAu; }
    if ((state & 0x04000000u) != 0u) { state = state * 1103515453u + 0xAFCDu; }
    else { state ^= 0xAFD9D5ABu; }
    if ((state & 0x08000000u) != 0u) { state = state * 1103515461u + 0x4E04u; }
    else { state ^= 0x4E114F5Cu; }
    if ((state & 0x10000000u) != 0u) { state = state * 1103515469u + 0xEC3Bu; }
    else { state ^= 0xEC48C90Du; }
    if ((state & 0x20000000u) != 0u) { state = state * 1103515477u + 0x8A72u; }
    else { state ^= 0x8A8042BEu; }
    if ((state & 0x40000000u) != 0u) { state = state * 1103515485u + 0x28A9u; }
    else { state ^= 0x28B7BC6Fu; }
    if ((state & 0x80000000u) != 0u) { state = state * 1103515493u + 0xC6E0u; }
    else { state ^= 0xC6EF3620u; }
    if ((state & 0x00000001u) != 0u) { state = state * 1103515501u + 0x6517u; }
    else { state ^= 0x6526AFD1u; }
    if ((state & 0x00000002u) != 0u) { state = state * 1103515509u + 0x034Eu; }
    else { state ^= 0x035E2982u; }
    if ((state & 0x00000004u) != 0u) { state = state * 1103515517u + 0xA185u; }
    else { state ^= 0xA195A333u; }
    if ((state & 0x00000008u) != 0u) { state = state * 1103515525u + 0x3FBCu; }
    else { state ^= 0x3FCD1CE4u; }
    if ((state & 0x00000010u) != 0u) { state = state * 1103515533u + 0xDDF3u; }
    else { state ^= 0xDE049695u; }
    if ((state & 0x00000020u) != 0u) { state = state * 1103515541u + 0x7C2Au; }
    else { state ^= 0x7C3C1046u; }
    if ((state & 0x00000040u) != 0u) { state = state * 1103515549u + 0x1A61u; }
    else { state ^= 0x1A7389F7u; }
    if ((state & 0x00000080u) != 0u) { state = state * 1103515557u + 0xB898u; }
    else { state ^= 0xB8AB03A8u; }
    if ((state & 0x00000100u) != 0u) { state = state * 1103515565u + 0x56CFu; }
    else { state ^= 0x56E27D59u; }
    if ((state & 0x00000200u) != 0u) { state = state * 1103515573u + 0xF506u; }
    else { state ^= 0xF519F70Au; }
    if ((state & 0x00000400u) != 0u) { state = state * 1103515581u + 0x933Du; }
    else { state ^= 0x935170BBu; }
    if ((state & 0x00000800u) != 0u) { state = state * 1103515589u + 0x3174u; }
    else { state ^= 0x3188EA6Cu; }
    if ((state & 0x00001000u) != 0u) { state = state * 1103515597u + 0xCFABu; }
    else { state ^= 0xCFC0641Du; }
    if ((state & 0x00002000u) != 0u) { state = state * 1103515605u + 0x6DE2u; }
    else { state ^= 0x6DF7DDCEu; }
    if ((state & 0x00004000u) != 0u) { state = state * 1103515613u + 0x0C19u; }
    else { state ^= 0x0C2F577Fu; }
    if ((state & 0x00008000u) != 0u) { state = state * 1103515621u + 0xAA50u; }
    else { state ^= 0xAA66D130u; }
    if ((state & 0x00010000u) != 0u) { state = state * 1103515629u + 0x4887u; }
    else { state ^= 0x489E4AE1u; }
    if ((state & 0x00020000u) != 0u) { state = state * 1103515637u + 0xE6BEu; }
    else { state ^= 0xE6D5C492u; }
    if ((state & 0x00040000u) != 0u) { state = state * 1103515645u + 0x84F5u; }
    else { state ^= 0x850D3E43u; }
    if ((state & 0x00080000u) != 0u) { state = state * 1103515653u + 0x232Cu; }
    else { state ^= 0x2344B7F4u; }
    if ((state & 0x00100000u) != 0u) { state = state * 1103515661u + 0xC163u; }
    else { state ^= 0xC17C31A5u; }
    if ((state & 0x00200000u) != 0u) { state = state * 1103515669u + 0x5F9Au; }
    else { state ^= 0x5FB3AB56u; }
    if ((state & 0x00400000u) != 0u) { state = state * 1103515677u + 0xFDD1u; }
    else { state ^= 0xFDEB2507u; }
    if ((state & 0x00800000u) != 0u) { state = state * 1103515685u + 0x9C08u; }
    else { state ^= 0x9C229EB8u; }
    if ((state & 0x01000000u) != 0u) { state = state * 1103515693u + 0x3A3Fu; }
    else { state ^= 0x3A5A1869u; }
    if ((state & 0x02000000u) != 0u) { state = state * 1103515701u + 0xD876u; }
    else { state ^= 0xD891921Au; }
    if ((state & 0x04000000u) != 0u) { state = state * 1103515709u + 0x76ADu; }
    else { state ^= 0x76C90BCBu; }
    if ((state & 0x08000000u) != 0u) { state = state * 1103515717u + 0x14E4u; }
    else { state ^= 0x1500857Cu; }
    if ((state & 0x10000000u) != 0u) { state = state * 1103515725u + 0xB31Bu; }
    else { state ^= 0xB337FF2Du; }
    if ((state & 0x20000000u) != 0u) { state = state * 1103515733u + 0x5152u; }
    else { state ^= 0x516F78DEu; }
    if ((state & 0x40000000u) != 0u) { state = state * 1103515741u + 0xEF89u; }
    else { state ^= 0xEFA6F28Fu; }
    if ((state & 0x80000000u) != 0u) { state = state * 1103515749u + 0x8DC0u; }
    else { state ^= 0x8DDE6C40u; }
    if ((state & 0x00000001u) != 0u) { state = state * 1103515757u + 0x2BF7u; }
    else { state ^= 0x2C15E5F1u; }
    if ((state & 0x00000002u) != 0u) { state = state * 1103515765u + 0xCA2Eu; }
    else { state ^= 0xCA4D5FA2u; }
    if ((state & 0x00000004u) != 0u) { state = state * 1103515773u + 0x6865u; }
    else { state ^= 0x6884D953u; }
    if ((state & 0x00000008u) != 0u) { state = state * 1103515781u + 0x069Cu; }
    else { state ^= 0x06BC5304u; }
    if ((state & 0x00000010u) != 0u) { state = state * 1103515789u + 0xA4D3u; }
    else { state ^= 0xA4F3CCB5u; }
    if ((state & 0x00000020u) != 0u) { state = state * 1103515797u + 0x430Au; }
    else { state ^= 0x432B4666u; }
    if ((state & 0x00000040u) != 0u) { state = state * 1103515805u + 0xE141u; }
    else { state ^= 0xE162C017u; }
    if ((state & 0x00000080u) != 0u) { state = state * 1103515813u + 0x7F78u; }
    else { state ^= 0x7F9A39C8u; }
    if ((state & 0x00000100u) != 0u) { state = state * 1103515821u + 0x1DAFu; }
    else { state ^= 0x1DD1B379u; }
    if ((state & 0x00000200u) != 0u) { state = state * 1103515829u + 0xBBE6u; }
    else { state ^= 0xBC092D2Au; }
    if ((state & 0x00000400u) != 0u) { state = state * 1103515837u + 0x5A1Du; }
    else { state ^= 0x5A40A6DBu; }
    if ((state & 0x00000800u) != 0u) { state = state * 1103515845u + 0xF854u; }
    else { state ^= 0xF878208Cu; }
    if ((state & 0x00001000u) != 0u) { state = state * 1103515853u + 0x968Bu; }
    else { state ^= 0x96AF9A3Du; }
    if ((state & 0x00002000u) != 0u) { state = state * 1103515861u + 0x34C2u; }
    else { state ^= 0x34E713EEu; }
    if ((state & 0x00004000u) != 0u) { state = state * 1103515869u + 0xD2F9u; }
    else { state ^= 0xD31E8D9Fu; }
    if ((state & 0x00008000u) != 0u) { state = state * 1103515877u + 0x7130u; }
    else { state ^= 0x71560750u; }
    if ((state & 0x00010000u) != 0u) { state = state * 1103515885u + 0x0F67u; }
    else { state ^= 0x0F8D8101u; }
    if ((state & 0x00020000u) != 0u) { state = state * 1103515893u + 0xAD9Eu; }
    else { state ^= 0xADC4FAB2u; }
    if ((state & 0x00040000u) != 0u) { state = state * 1103515901u + 0x4BD5u; }
    else { state ^= 0x4BFC7463u; }
    if ((state & 0x00080000u) != 0u) { state = state * 1103515909u + 0xEA0Cu; }
    else { state ^= 0xEA33EE14u; }
    if ((state & 0x00100000u) != 0u) { state = state * 1103515917u + 0x8843u; }
    else { state ^= 0x886B67C5u; }
    if ((state & 0x00200000u) != 0u) { state = state * 1103515925u + 0x267Au; }
    else { state ^= 0x26A2E176u; }
    if ((state & 0x00400000u) != 0u) { state = state * 1103515933u + 0xC4B1u; }
    else { state ^= 0xC4DA5B27u; }
    if ((state & 0x00800000u) != 0u) { state = state * 1103515941u + 0x62E8u; }
    else { state ^= 0x6311D4D8u; }
    if ((state & 0x01000000u) != 0u) { state = state * 1103515949u + 0x011Fu; }
    else { state ^= 0x01494E89u; }
    if ((state & 0x02000000u) != 0u) { state = state * 1103515957u + 0x9F56u; }
    else { state ^= 0x9F80C83Au; }
    if ((state & 0x04000000u) != 0u) { state = state * 1103515965u + 0x3D8Du; }
    else { state ^= 0x3DB841EBu; }
    if ((state & 0x08000000u) != 0u) { state = state * 1103515973u + 0xDBC4u; }
    else { state ^= 0xDBEFBB9Cu; }
    if ((state & 0x10000000u) != 0u) { state = state * 1103515981u + 0x79FBu; }
    else { state ^= 0x7A27354Du; }
    if ((state & 0x20000000u) != 0u) { state = state * 1103515989u + 0x1832u; }
    else { state ^= 0x185EAEFEu; }
    if ((state & 0x40000000u) != 0u) { state = state * 1103515997u + 0xB669u; }
    else { state ^= 0xB69628AFu; }
    if ((state & 0x80000000u) != 0u) { state = state * 1103516005u + 0x54A0u; }
    else { state ^= 0x54CDA260u; }
    if ((state & 0x00000001u) != 0u) { state = state * 1103516013u + 0xF2D7u; }
    else { state ^= 0xF3051C11u; }
    if ((state & 0x00000002u) != 0u) { state = state * 1103516021u + 0x910Eu; }
    else { state ^= 0x913C95C2u; }
    if ((state & 0x00000004u) != 0u) { state = state * 1103516029u + 0x2F45u; }
    else { state ^= 0x2F740F73u; }
    if ((state & 0x00000008u) != 0u) { state = state * 1103516037u + 0xCD7Cu; }
    else { state ^= 0xCDAB8924u; }
    if ((state & 0x00000010u) != 0u) { state = state * 1103516045u + 0x6BB3u; }
    else { state ^= 0x6BE302D5u; }
    if ((state & 0x00000020u) != 0u) { state = state * 1103516053u + 0x09EAu; }
    else { state ^= 0x0A1A7C86u; }
    if ((state & 0x00000040u) != 0u) { state = state * 1103516061u + 0xA821u; }
    else { state ^= 0xA851F637u; }
    if ((state & 0x00000080u) != 0u) { state = state * 1103516069u + 0x4658u; }
    else { state ^= 0x46896FE8u; }
    if ((state & 0x00000100u) != 0u) { state = state * 1103516077u + 0xE48Fu; }
    else { state ^= 0xE4C0E999u; }
    if ((state & 0x00000200u) != 0u) { state = state * 1103516085u + 0x82C6u; }
    else { state ^= 0x82F8634Au; }
    if ((state & 0x00000400u) != 0u) { state = state * 1103516093u + 0x20FDu; }
    else { state ^= 0x212FDCFBu; }
    if ((state & 0x00000800u) != 0u) { state = state * 1103516101u + 0xBF34u; }
    else { state ^= 0xBF6756ACu; }
    if ((state & 0x00001000u) != 0u) { state = state * 1103516109u + 0x5D6Bu; }
    else { state ^= 0x5D9ED05Du; }
    if ((state & 0x00002000u) != 0u) { state = state * 1103516117u + 0xFBA2u; }
    else { state ^= 0xFBD64A0Eu; }
    if ((state & 0x00004000u) != 0u) { state = state * 1103516125u + 0x99D9u; }
    else { state ^= 0x9A0DC3BFu; }
    if ((state & 0x00008000u) != 0u) { state = state * 1103516133u + 0x3810u; }
    else { state ^= 0x38453D70u; }
    if ((state & 0x00010000u) != 0u) { state = state * 1103516141u + 0xD647u; }
    else { state ^= 0xD67CB721u; }
    if ((state & 0x00020000u) != 0u) { state = state * 1103516149u + 0x747Eu; }
    else { state ^= 0x74B430D2u; }
    if ((state & 0x00040000u) != 0u) { state = state * 1103516157u + 0x12B5u; }
    else { state ^= 0x12EBAA83u; }
    if ((state & 0x00080000u) != 0u) { state = state * 1103516165u + 0xB0ECu; }
    else { state ^= 0xB1232434u; }
    if ((state & 0x00100000u) != 0u) { state = state * 1103516173u + 0x4F23u; }
    else { state ^= 0x4F5A9DE5u; }
    if ((state & 0x00200000u) != 0u) { state = state * 1103516181u + 0xED5Au; }
    else { state ^= 0xED921796u; }
    if ((state & 0x00400000u) != 0u) { state = state * 1103516189u + 0x8B91u; }
    else { state ^= 0x8BC99147u; }
    if ((state & 0x00800000u) != 0u) { state = state * 1103516197u + 0x29C8u; }
    else { state ^= 0x2A010AF8u; }
    if ((state & 0x01000000u) != 0u) { state = state * 1103516205u + 0xC7FFu; }
    else { state ^= 0xC83884A9u; }
    if ((state & 0x02000000u) != 0u) { state = state * 1103516213u + 0x6636u; }
    else { state ^= 0x666FFE5Au; }
    if ((state & 0x04000000u) != 0u) { state = state * 1103516221u + 0x046Du; }
    else { state ^= 0x04A7780Bu; }
    if ((state & 0x08000000u) != 0u) { state = state * 1103516229u + 0xA2A4u; }
    else { state ^= 0xA2DEF1BCu; }
    if ((state & 0x10000000u) != 0u) { state = state * 1103516237u + 0x40DBu; }
    else { state ^= 0x41166B6Du; }
    if ((state & 0x20000000u) != 0u) { state = state * 1103516245u + 0xDF12u; }
    else { state ^= 0xDF4DE51Eu; }
    if ((state & 0x40000000u) != 0u) { state = state * 1103516253u + 0x7D49u; }
    else { state ^= 0x7D855ECFu; }
    if ((state & 0x80000000u) != 0u) { state = state * 1103516261u + 0x1B80u; }
    else { state ^= 0x1BBCD880u; }
    if ((state & 0x00000001u) != 0u) { state = state * 1103516269u + 0xB9B7u; }
    else { state ^= 0xB9F45231u; }
    if ((state & 0x00000002u) != 0u) { state = state * 1103516277u + 0x57EEu; }
    else { state ^= 0x582BCBE2u; }
    if ((state & 0x00000004u) != 0u) { state = state * 1103516285u + 0xF625u; }
    else { state ^= 0xF6634593u; }
    if ((state & 0x00000008u) != 0u) { state = state * 1103516293u + 0x945Cu; }
    else { state ^= 0x949ABF44u; }
    if ((state & 0x00000010u) != 0u) { state = state * 1103516301u + 0x3293u; }
    else { state ^= 0x32D238F5u; }
    if ((state & 0x00000020u) != 0u) { state = state * 1103516309u + 0xD0CAu; }
    else { state ^= 0xD109B2A6u; }
    if ((state & 0x00000040u) != 0u) { state = state * 1103516317u + 0x6F01u; }
    else { state ^= 0x6F412C57u; }
    if ((state & 0x00000080u) != 0u) { state = state * 1103516325u + 0x0D38u; }
    else { state ^= 0x0D78A608u; }
    if ((state & 0x00000100u) != 0u) { state = state * 1103516333u + 0xAB6Fu; }
    else { state ^= 0xABB01FB9u; }
    if ((state & 0x00000200u) != 0u) { state = state * 1103516341u + 0x49A6u; }
    else { state ^= 0x49E7996Au; }
    if ((state & 0x00000400u) != 0u) { state = state * 1103516349u + 0xE7DDu; }
    else { state ^= 0xE81F131Bu; }
    if ((state & 0x00000800u) != 0u) { state = state * 1103516357u + 0x8614u; }
    else { state ^= 0x86568CCCu; }
    if ((state & 0x00001000u) != 0u) { state = state * 1103516365u + 0x244Bu; }
    else { state ^= 0x248E067Du; }
    if ((state & 0x00002000u) != 0u) { state = state * 1103516373u + 0xC282u; }
    else { state ^= 0xC2C5802Eu; }
    if ((state & 0x00004000u) != 0u) { state = state * 1103516381u + 0x60B9u; }
    else { state ^= 0x60FCF9DFu; }
    if ((state & 0x00008000u) != 0u) { state = state * 1103516389u + 0xFEF0u; }
    else { state ^= 0xFF347390u; }
    if ((state & 0x00010000u) != 0u) { state = state * 1103516397u + 0x9D27u; }
    else { state ^= 0x9D6BED41u; }
    if ((state & 0x00020000u) != 0u) { state = state * 1103516405u + 0x3B5Eu; }
    else { state ^= 0x3BA366F2u; }
    if ((state & 0x00040000u) != 0u) { state = state * 1103516413u + 0xD995u; }
    else { state ^= 0xD9DAE0A3u; }
    if ((state & 0x00080000u) != 0u) { state = state * 1103516421u + 0x77CCu; }
    else { state ^= 0x78125A54u; }
    if ((state & 0x00100000u) != 0u) { state = state * 1103516429u + 0x1603u; }
    else { state ^= 0x1649D405u; }
    if ((state & 0x00200000u) != 0u) { state = state * 1103516437u + 0xB43Au; }
    else { state ^= 0xB4814DB6u; }
    if ((state & 0x00400000u) != 0u) { state = state * 1103516445u + 0x5271u; }
    else { state ^= 0x52B8C767u; }
    if ((state & 0x00800000u) != 0u) { state = state * 1103516453u + 0xF0A8u; }
    else { state ^= 0xF0F04118u; }
    if ((state & 0x01000000u) != 0u) { state = state * 1103516461u + 0x8EDFu; }
    else { state ^= 0x8F27BAC9u; }
    if ((state & 0x02000000u) != 0u) { state = state * 1103516469u + 0x2D16u; }
    else { state ^= 0x2D5F347Au; }
    if ((state & 0x04000000u) != 0u) { state = state * 1103516477u + 0xCB4Du; }
    else { state ^= 0xCB96AE2Bu; }
    if ((state & 0x08000000u) != 0u) { state = state * 1103516485u + 0x6984u; }
    else { state ^= 0x69CE27DCu; }
    if ((state & 0x10000000u) != 0u) { state = state * 1103516493u + 0x07BBu; }
    else { state ^= 0x0805A18Du; }
    if ((state & 0x20000000u) != 0u) { state = state * 1103516501u + 0xA5F2u; }
    else { state ^= 0xA63D1B3Eu; }
    if ((state & 0x40000000u) != 0u) { state = state * 1103516509u + 0x4429u; }
    else { state ^= 0x447494EFu; }
    if ((state & 0x80000000u) != 0u) { state = state * 1103516517u + 0xE260u; }
    else { state ^= 0xE2AC0EA0u; }
    if ((state & 0x00000001u) != 0u) { state = state * 1103516525u + 0x8097u; }
    else { state ^= 0x80E38851u; }
    if ((state & 0x00000002u) != 0u) { state = state * 1103516533u + 0x1ECEu; }
    else { state ^= 0x1F1B0202u; }
    if ((state & 0x00000004u) != 0u) { state = state * 1103516541u + 0xBD05u; }
    else { state ^= 0xBD527BB3u; }
    if ((state & 0x00000008u) != 0u) { state = state * 1103516549u + 0x5B3Cu; }
    else { state ^= 0x5B89F564u; }
    if ((state & 0x00000010u) != 0u) { state = state * 1103516557u + 0xF973u; }
    else { state ^= 0xF9C16F15u; }
    if ((state & 0x00000020u) != 0u) { state = state * 1103516565u + 0x97AAu; }
    else { state ^= 0x97F8E8C6u; }
    if ((state & 0x00000040u) != 0u) { state = state * 1103516573u + 0x35E1u; }
    else { state ^= 0x36306277u; }
    if ((state & 0x00000080u) != 0u) { state = state * 1103516581u + 0xD418u; }
    else { state ^= 0xD467DC28u; }
    if ((state & 0x00000100u) != 0u) { state = state * 1103516589u + 0x724Fu; }
    else { state ^= 0x729F55D9u; }
    if ((state & 0x00000200u) != 0u) { state = state * 1103516597u + 0x1086u; }
    else { state ^= 0x10D6CF8Au; }
    if ((state & 0x00000400u) != 0u) { state = state * 1103516605u + 0xAEBDu; }
    else { state ^= 0xAF0E493Bu; }
    if ((state & 0x00000800u) != 0u) { state = state * 1103516613u + 0x4CF4u; }
    else { state ^= 0x4D45C2ECu; }
    if ((state & 0x00001000u) != 0u) { state = state * 1103516621u + 0xEB2Bu; }
    else { state ^= 0xEB7D3C9Du; }
    if ((state & 0x00002000u) != 0u) { state = state * 1103516629u + 0x8962u; }
    else { state ^= 0x89B4B64Eu; }
    if ((state & 0x00004000u) != 0u) { state = state * 1103516637u + 0x2799u; }
    else { state ^= 0x27EC2FFFu; }
    if ((state & 0x00008000u) != 0u) { state = state * 1103516645u + 0xC5D0u; }
    else { state ^= 0xC623A9B0u; }
    if ((state & 0x00010000u) != 0u) { state = state * 1103516653u + 0x6407u; }
    else { state ^= 0x645B2361u; }
    if ((state & 0x00020000u) != 0u) { state = state * 1103516661u + 0x023Eu; }
    else { state ^= 0x02929D12u; }
    if ((state & 0x00040000u) != 0u) { state = state * 1103516669u + 0xA075u; }
    else { state ^= 0xA0CA16C3u; }
    if ((state & 0x00080000u) != 0u) { state = state * 1103516677u + 0x3EACu; }
    else { state ^= 0x3F019074u; }
    if ((state & 0x00100000u) != 0u) { state = state * 1103516685u + 0xDCE3u; }
    else { state ^= 0xDD390A25u; }
    if ((state & 0x00200000u) != 0u) { state = state * 1103516693u + 0x7B1Au; }
    else { state ^= 0x7B7083D6u; }
    if ((state & 0x00400000u) != 0u) { state = state * 1103516701u + 0x1951u; }
    else { state ^= 0x19A7FD87u; }
    if ((state & 0x00800000u) != 0u) { state = state * 1103516709u + 0xB788u; }
    else { state ^= 0xB7DF7738u; }
    if ((state & 0x01000000u) != 0u) { state = state * 1103516717u + 0x55BFu; }
    else { state ^= 0x5616F0E9u; }
    if ((state & 0x02000000u) != 0u) { state = state * 1103516725u + 0xF3F6u; }
    else { state ^= 0xF44E6A9Au; }
    if ((state & 0x04000000u) != 0u) { state = state * 1103516733u + 0x922Du; }
    else { state ^= 0x9285E44Bu; }
    if ((state & 0x08000000u) != 0u) { state = state * 1103516741u + 0x3064u; }
    else { state ^= 0x30BD5DFCu; }
    if ((state & 0x10000000u) != 0u) { state = state * 1103516749u + 0xCE9Bu; }
    else { state ^= 0xCEF4D7ADu; }
    if ((state & 0x20000000u) != 0u) { state = state * 1103516757u + 0x6CD2u; }
    else { state ^= 0x6D2C515Eu; }
    if ((state & 0x40000000u) != 0u) { state = state * 1103516765u + 0x0B09u; }
    else { state ^= 0x0B63CB0Fu; }
    if ((state & 0x80000000u) != 0u) { state = state * 1103516773u + 0xA940u; }
    else { state ^= 0xA99B44C0u; }
    if ((state & 0x00000001u) != 0u) { state = state * 1103516781u + 0x4777u; }
    else { state ^= 0x47D2BE71u; }
    if ((state & 0x00000002u) != 0u) { state = state * 1103516789u + 0xE5AEu; }
    else { state ^= 0xE60A3822u; }
    if ((state & 0x00000004u) != 0u) { state = state * 1103516797u + 0x83E5u; }
    else { state ^= 0x8441B1D3u; }
    if ((state & 0x00000008u) != 0u) { state = state * 1103516805u + 0x221Cu; }
    else { state ^= 0x22792B84u; }
    if ((state & 0x00000010u) != 0u) { state = state * 1103516813u + 0xC053u; }
    else { state ^= 0xC0B0A535u; }
    if ((state & 0x00000020u) != 0u) { state = state * 1103516821u + 0x5E8Au; }
    else { state ^= 0x5EE81EE6u; }
    if ((state & 0x00000040u) != 0u) { state = state * 1103516829u + 0xFCC1u; }
    else { state ^= 0xFD1F9897u; }
    if ((state & 0x00000080u) != 0u) { state = state * 1103516837u + 0x9AF8u; }
    else { state ^= 0x9B571248u; }

    return state;
}
