#include <stdint.h>

/* Scale stress: switch width.
 *
 * `wide154_dense_switch` has 256 contiguous cases returning distinct
 * constants, which compilers lower to a constant lookup table rather than
 * a jump table -- the switch disappears into an array the decompiler has to
 * find. `wide154_dense_effects` has 208 contiguous cases with real side
 * effects and fallthrough groups, which stays a true jump table.
 * `wide154_sparse_switch` has 200 cases spread on a stride of 4099 across
 * ~800k, which lowers to a binary comparison tree instead.
 *
 * Each selector is reduced modulo slightly more than the case count, so
 * every input lands on a real case (with a small window left over for the
 * default) and the differential exercises the table rather than the
 * fallback. Every call is one table lookup or one tree descent. */

#define WIDE154_DENSE_SPAN 260u
#define WIDE154_EFFECT_SPAN 216u
#define WIDE154_SPARSE_SPAN 205u
#define WIDE154_SPARSE_STRIDE 4099u
#define WIDE154_SLOTS 16

__attribute__((noinline)) int32_t wide154_dense_switch(int32_t selector) {
    int32_t index = (int32_t)((uint32_t)selector % WIDE154_DENSE_SPAN);

    switch (index) {
    case 0: return 1000;
    case 1: return 1007;
    case 2: return 1014;
    case 3: return 1021;
    case 4: return 1028;
    case 5: return 1035;
    case 6: return 1042;
    case 7: return 1049;
    case 8: return 1056;
    case 9: return 1063;
    case 10: return 1070;
    case 11: return 1077;
    case 12: return 1084;
    case 13: return 1091;
    case 14: return 1098;
    case 15: return 1105;
    case 16: return 1112;
    case 17: return 1119;
    case 18: return 1126;
    case 19: return 1133;
    case 20: return 1140;
    case 21: return 1147;
    case 22: return 1154;
    case 23: return 1161;
    case 24: return 1168;
    case 25: return 1175;
    case 26: return 1182;
    case 27: return 1189;
    case 28: return 1196;
    case 29: return 1203;
    case 30: return 1210;
    case 31: return 1217;
    case 32: return 1224;
    case 33: return 1231;
    case 34: return 1238;
    case 35: return 1245;
    case 36: return 1252;
    case 37: return 1259;
    case 38: return 1266;
    case 39: return 1273;
    case 40: return 1280;
    case 41: return 1287;
    case 42: return 1294;
    case 43: return 1301;
    case 44: return 1308;
    case 45: return 1315;
    case 46: return 1322;
    case 47: return 1329;
    case 48: return 1336;
    case 49: return 1343;
    case 50: return 1350;
    case 51: return 1357;
    case 52: return 1364;
    case 53: return 1371;
    case 54: return 1378;
    case 55: return 1385;
    case 56: return 1392;
    case 57: return 1399;
    case 58: return 1406;
    case 59: return 1413;
    case 60: return 1420;
    case 61: return 1427;
    case 62: return 1434;
    case 63: return 1441;
    case 64: return 1448;
    case 65: return 1455;
    case 66: return 1462;
    case 67: return 1469;
    case 68: return 1476;
    case 69: return 1483;
    case 70: return 1490;
    case 71: return 1497;
    case 72: return 1504;
    case 73: return 1511;
    case 74: return 1518;
    case 75: return 1525;
    case 76: return 1532;
    case 77: return 1539;
    case 78: return 1546;
    case 79: return 1553;
    case 80: return 1560;
    case 81: return 1567;
    case 82: return 1574;
    case 83: return 1581;
    case 84: return 1588;
    case 85: return 1595;
    case 86: return 1602;
    case 87: return 1609;
    case 88: return 1616;
    case 89: return 1623;
    case 90: return 1630;
    case 91: return 1637;
    case 92: return 1644;
    case 93: return 1651;
    case 94: return 1658;
    case 95: return 1665;
    case 96: return 1672;
    case 97: return 1679;
    case 98: return 1686;
    case 99: return 1693;
    case 100: return 1700;
    case 101: return 1707;
    case 102: return 1714;
    case 103: return 1721;
    case 104: return 1728;
    case 105: return 1735;
    case 106: return 1742;
    case 107: return 1749;
    case 108: return 1756;
    case 109: return 1763;
    case 110: return 1770;
    case 111: return 1777;
    case 112: return 1784;
    case 113: return 1791;
    case 114: return 1798;
    case 115: return 1805;
    case 116: return 1812;
    case 117: return 1819;
    case 118: return 1826;
    case 119: return 1833;
    case 120: return 1840;
    case 121: return 1847;
    case 122: return 1854;
    case 123: return 1861;
    case 124: return 1868;
    case 125: return 1875;
    case 126: return 1882;
    case 127: return 1889;
    case 128: return 1896;
    case 129: return 1903;
    case 130: return 1910;
    case 131: return 1917;
    case 132: return 1924;
    case 133: return 1931;
    case 134: return 1938;
    case 135: return 1945;
    case 136: return 1952;
    case 137: return 1959;
    case 138: return 1966;
    case 139: return 1973;
    case 140: return 1980;
    case 141: return 1987;
    case 142: return 1994;
    case 143: return 2001;
    case 144: return 2008;
    case 145: return 2015;
    case 146: return 2022;
    case 147: return 2029;
    case 148: return 2036;
    case 149: return 2043;
    case 150: return 2050;
    case 151: return 2057;
    case 152: return 2064;
    case 153: return 2071;
    case 154: return 2078;
    case 155: return 2085;
    case 156: return 2092;
    case 157: return 2099;
    case 158: return 2106;
    case 159: return 2113;
    case 160: return 2120;
    case 161: return 2127;
    case 162: return 2134;
    case 163: return 2141;
    case 164: return 2148;
    case 165: return 2155;
    case 166: return 2162;
    case 167: return 2169;
    case 168: return 2176;
    case 169: return 2183;
    case 170: return 2190;
    case 171: return 2197;
    case 172: return 2204;
    case 173: return 2211;
    case 174: return 2218;
    case 175: return 2225;
    case 176: return 2232;
    case 177: return 2239;
    case 178: return 2246;
    case 179: return 2253;
    case 180: return 2260;
    case 181: return 2267;
    case 182: return 2274;
    case 183: return 2281;
    case 184: return 2288;
    case 185: return 2295;
    case 186: return 2302;
    case 187: return 2309;
    case 188: return 2316;
    case 189: return 2323;
    case 190: return 2330;
    case 191: return 2337;
    case 192: return 2344;
    case 193: return 2351;
    case 194: return 2358;
    case 195: return 2365;
    case 196: return 2372;
    case 197: return 2379;
    case 198: return 2386;
    case 199: return 2393;
    case 200: return 2400;
    case 201: return 2407;
    case 202: return 2414;
    case 203: return 2421;
    case 204: return 2428;
    case 205: return 2435;
    case 206: return 2442;
    case 207: return 2449;
    case 208: return 2456;
    case 209: return 2463;
    case 210: return 2470;
    case 211: return 2477;
    case 212: return 2484;
    case 213: return 2491;
    case 214: return 2498;
    case 215: return 2505;
    case 216: return 2512;
    case 217: return 2519;
    case 218: return 2526;
    case 219: return 2533;
    case 220: return 2540;
    case 221: return 2547;
    case 222: return 2554;
    case 223: return 2561;
    case 224: return 2568;
    case 225: return 2575;
    case 226: return 2582;
    case 227: return 2589;
    case 228: return 2596;
    case 229: return 2603;
    case 230: return 2610;
    case 231: return 2617;
    case 232: return 2624;
    case 233: return 2631;
    case 234: return 2638;
    case 235: return 2645;
    case 236: return 2652;
    case 237: return 2659;
    case 238: return 2666;
    case 239: return 2673;
    case 240: return 2680;
    case 241: return 2687;
    case 242: return 2694;
    case 243: return 2701;
    case 244: return 2708;
    case 245: return 2715;
    case 246: return 2722;
    case 247: return 2729;
    case 248: return 2736;
    case 249: return 2743;
    case 250: return 2750;
    case 251: return 2757;
    case 252: return 2764;
    case 253: return 2771;
    case 254: return 2778;
    case 255: return 2785;
    default: return -1;
    }
}

/* Contiguous cases with observable effects. Every fourth case falls through
 * into the next one, and the case bodies cycle through five different
 * shapes (fold, rotate, branch, counted loop, guarded loop with a memory
 * effect) -- with one uniform body shape clang -O2 tabulates the per-case
 * constants and the whole 208-case switch shrinks to five basic blocks. */
__attribute__((noinline)) int32_t
wide154_dense_effects(int32_t selector, int32_t *out, int32_t slots) {
    int32_t index;
    int32_t position;
    uint32_t acc = 0x1F123BB5u;

    if (out == 0 || slots < 1 || slots > WIDE154_SLOTS) {
        return -1;
    }
    for (position = 0; position < slots; ++position) {
        out[position] = 0;
    }
    index = (int32_t)((uint32_t)selector % WIDE154_EFFECT_SPAN);

    switch (index) {
    case 0:
        acc = acc * 1103515245u + 0x6075u;
        __attribute__((fallthrough));
    case 1:
        acc ^= 0xDA26u;
        acc = (acc << 2u) | (acc >> 30u);
        __attribute__((fallthrough));
    case 2:
        if ((acc & 0x00000004u) != 0u) { acc += 0x53D7u; }
        else { acc ^= 1103515293u; }
        __attribute__((fallthrough));
    case 3:
        for (position = 0; position < 2; ++position) {
            acc = acc * 1103515317u + (uint32_t)position;
        }
        break;
    case 4:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103515341u + 0x4739u;
        }
        out[(uint32_t)(index + 4) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        __attribute__((fallthrough));
    case 5:
        acc = acc * 1103515365u + 0xC0EAu;
        __attribute__((fallthrough));
    case 6:
        acc ^= 0x3A9Bu;
        acc = (acc << 7u) | (acc >> 25u);
        __attribute__((fallthrough));
    case 7:
        if ((acc & 0x00000080u) != 0u) { acc += 0xB44Cu; }
        else { acc ^= 1103515413u; }
        break;
    case 8:
        for (position = 0; position < 4; ++position) {
            acc = acc * 1103515437u + (uint32_t)position;
        }
        __attribute__((fallthrough));
    case 9:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103515461u + 0xA7AEu;
        }
        out[(uint32_t)(index + 9) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        __attribute__((fallthrough));
    case 10:
        acc = acc * 1103515485u + 0x215Fu;
        __attribute__((fallthrough));
    case 11:
        acc ^= 0x9B10u;
        acc = (acc << 12u) | (acc >> 20u);
        break;
    case 12:
        if ((acc & 0x00001000u) != 0u) { acc += 0x14C1u; }
        else { acc ^= 1103515533u; }
        __attribute__((fallthrough));
    case 13:
        for (position = 0; position < 3; ++position) {
            acc = acc * 1103515557u + (uint32_t)position;
        }
        __attribute__((fallthrough));
    case 14:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103515581u + 0x0823u;
        }
        out[(uint32_t)(index + 14) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        __attribute__((fallthrough));
    case 15:
        acc = acc * 1103515605u + 0x81D4u;
        break;
    case 16:
        acc ^= 0xFB85u;
        acc = (acc << 17u) | (acc >> 15u);
        __attribute__((fallthrough));
    case 17:
        if ((acc & 0x00020000u) != 0u) { acc += 0x7536u; }
        else { acc ^= 1103515653u; }
        __attribute__((fallthrough));
    case 18:
        for (position = 0; position < 2; ++position) {
            acc = acc * 1103515677u + (uint32_t)position;
        }
        __attribute__((fallthrough));
    case 19:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103515701u + 0x6898u;
        }
        out[(uint32_t)(index + 19) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        break;
    case 20:
        acc = acc * 1103515725u + 0xE249u;
        __attribute__((fallthrough));
    case 21:
        acc ^= 0x5BFAu;
        acc = (acc << 22u) | (acc >> 10u);
        __attribute__((fallthrough));
    case 22:
        if ((acc & 0x00400000u) != 0u) { acc += 0xD5ABu; }
        else { acc ^= 1103515773u; }
        __attribute__((fallthrough));
    case 23:
        for (position = 0; position < 4; ++position) {
            acc = acc * 1103515797u + (uint32_t)position;
        }
        break;
    case 24:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103515821u + 0xC90Du;
        }
        out[(uint32_t)(index + 24) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        __attribute__((fallthrough));
    case 25:
        acc = acc * 1103515845u + 0x42BEu;
        __attribute__((fallthrough));
    case 26:
        acc ^= 0xBC6Fu;
        acc = (acc << 27u) | (acc >> 5u);
        __attribute__((fallthrough));
    case 27:
        if ((acc & 0x00000008u) != 0u) { acc += 0x3620u; }
        else { acc ^= 1103515893u; }
        break;
    case 28:
        for (position = 0; position < 3; ++position) {
            acc = acc * 1103515917u + (uint32_t)position;
        }
        __attribute__((fallthrough));
    case 29:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103515941u + 0x2982u;
        }
        out[(uint32_t)(index + 29) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        __attribute__((fallthrough));
    case 30:
        acc = acc * 1103515965u + 0xA333u;
        __attribute__((fallthrough));
    case 31:
        acc ^= 0x1CE4u;
        acc = (acc << 1u) | (acc >> 31u);
        break;
    case 32:
        if ((acc & 0x00000100u) != 0u) { acc += 0x9695u; }
        else { acc ^= 1103516013u; }
        __attribute__((fallthrough));
    case 33:
        for (position = 0; position < 2; ++position) {
            acc = acc * 1103516037u + (uint32_t)position;
        }
        __attribute__((fallthrough));
    case 34:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103516061u + 0x89F7u;
        }
        out[(uint32_t)(index + 34) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        __attribute__((fallthrough));
    case 35:
        acc = acc * 1103516085u + 0x03A8u;
        break;
    case 36:
        acc ^= 0x7D59u;
        acc = (acc << 6u) | (acc >> 26u);
        __attribute__((fallthrough));
    case 37:
        if ((acc & 0x00002000u) != 0u) { acc += 0xF70Au; }
        else { acc ^= 1103516133u; }
        __attribute__((fallthrough));
    case 38:
        for (position = 0; position < 4; ++position) {
            acc = acc * 1103516157u + (uint32_t)position;
        }
        __attribute__((fallthrough));
    case 39:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103516181u + 0xEA6Cu;
        }
        out[(uint32_t)(index + 39) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        break;
    case 40:
        acc = acc * 1103516205u + 0x641Du;
        __attribute__((fallthrough));
    case 41:
        acc ^= 0xDDCEu;
        acc = (acc << 11u) | (acc >> 21u);
        __attribute__((fallthrough));
    case 42:
        if ((acc & 0x00040000u) != 0u) { acc += 0x577Fu; }
        else { acc ^= 1103516253u; }
        __attribute__((fallthrough));
    case 43:
        for (position = 0; position < 3; ++position) {
            acc = acc * 1103516277u + (uint32_t)position;
        }
        break;
    case 44:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103516301u + 0x4AE1u;
        }
        out[(uint32_t)(index + 44) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        __attribute__((fallthrough));
    case 45:
        acc = acc * 1103516325u + 0xC492u;
        __attribute__((fallthrough));
    case 46:
        acc ^= 0x3E43u;
        acc = (acc << 16u) | (acc >> 16u);
        __attribute__((fallthrough));
    case 47:
        if ((acc & 0x00800000u) != 0u) { acc += 0xB7F4u; }
        else { acc ^= 1103516373u; }
        break;
    case 48:
        for (position = 0; position < 2; ++position) {
            acc = acc * 1103516397u + (uint32_t)position;
        }
        __attribute__((fallthrough));
    case 49:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103516421u + 0xAB56u;
        }
        out[(uint32_t)(index + 49) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        __attribute__((fallthrough));
    case 50:
        acc = acc * 1103516445u + 0x2507u;
        __attribute__((fallthrough));
    case 51:
        acc ^= 0x9EB8u;
        acc = (acc << 21u) | (acc >> 11u);
        break;
    case 52:
        if ((acc & 0x00000010u) != 0u) { acc += 0x1869u; }
        else { acc ^= 1103516493u; }
        __attribute__((fallthrough));
    case 53:
        for (position = 0; position < 4; ++position) {
            acc = acc * 1103516517u + (uint32_t)position;
        }
        __attribute__((fallthrough));
    case 54:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103516541u + 0x0BCBu;
        }
        out[(uint32_t)(index + 54) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        __attribute__((fallthrough));
    case 55:
        acc = acc * 1103516565u + 0x857Cu;
        break;
    case 56:
        acc ^= 0xFF2Du;
        acc = (acc << 26u) | (acc >> 6u);
        __attribute__((fallthrough));
    case 57:
        if ((acc & 0x00000200u) != 0u) { acc += 0x78DEu; }
        else { acc ^= 1103516613u; }
        __attribute__((fallthrough));
    case 58:
        for (position = 0; position < 3; ++position) {
            acc = acc * 1103516637u + (uint32_t)position;
        }
        __attribute__((fallthrough));
    case 59:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103516661u + 0x6C40u;
        }
        out[(uint32_t)(index + 59) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        break;
    case 60:
        acc = acc * 1103516685u + 0xE5F1u;
        __attribute__((fallthrough));
    case 61:
        acc ^= 0x5FA2u;
        acc = (acc << 31u) | (acc >> 1u);
        __attribute__((fallthrough));
    case 62:
        if ((acc & 0x00004000u) != 0u) { acc += 0xD953u; }
        else { acc ^= 1103516733u; }
        __attribute__((fallthrough));
    case 63:
        for (position = 0; position < 2; ++position) {
            acc = acc * 1103516757u + (uint32_t)position;
        }
        break;
    case 64:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103516781u + 0xCCB5u;
        }
        out[(uint32_t)(index + 64) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        __attribute__((fallthrough));
    case 65:
        acc = acc * 1103516805u + 0x4666u;
        __attribute__((fallthrough));
    case 66:
        acc ^= 0xC017u;
        acc = (acc << 5u) | (acc >> 27u);
        __attribute__((fallthrough));
    case 67:
        if ((acc & 0x00080000u) != 0u) { acc += 0x39C8u; }
        else { acc ^= 1103516853u; }
        break;
    case 68:
        for (position = 0; position < 4; ++position) {
            acc = acc * 1103516877u + (uint32_t)position;
        }
        __attribute__((fallthrough));
    case 69:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103516901u + 0x2D2Au;
        }
        out[(uint32_t)(index + 69) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        __attribute__((fallthrough));
    case 70:
        acc = acc * 1103516925u + 0xA6DBu;
        __attribute__((fallthrough));
    case 71:
        acc ^= 0x208Cu;
        acc = (acc << 10u) | (acc >> 22u);
        break;
    case 72:
        if ((acc & 0x00000001u) != 0u) { acc += 0x9A3Du; }
        else { acc ^= 1103516973u; }
        __attribute__((fallthrough));
    case 73:
        for (position = 0; position < 3; ++position) {
            acc = acc * 1103516997u + (uint32_t)position;
        }
        __attribute__((fallthrough));
    case 74:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103517021u + 0x8D9Fu;
        }
        out[(uint32_t)(index + 74) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        __attribute__((fallthrough));
    case 75:
        acc = acc * 1103517045u + 0x0750u;
        break;
    case 76:
        acc ^= 0x8101u;
        acc = (acc << 15u) | (acc >> 17u);
        __attribute__((fallthrough));
    case 77:
        if ((acc & 0x00000020u) != 0u) { acc += 0xFAB2u; }
        else { acc ^= 1103517093u; }
        __attribute__((fallthrough));
    case 78:
        for (position = 0; position < 2; ++position) {
            acc = acc * 1103517117u + (uint32_t)position;
        }
        __attribute__((fallthrough));
    case 79:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103517141u + 0xEE14u;
        }
        out[(uint32_t)(index + 79) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        break;
    case 80:
        acc = acc * 1103517165u + 0x67C5u;
        __attribute__((fallthrough));
    case 81:
        acc ^= 0xE176u;
        acc = (acc << 20u) | (acc >> 12u);
        __attribute__((fallthrough));
    case 82:
        if ((acc & 0x00000400u) != 0u) { acc += 0x5B27u; }
        else { acc ^= 1103517213u; }
        __attribute__((fallthrough));
    case 83:
        for (position = 0; position < 4; ++position) {
            acc = acc * 1103517237u + (uint32_t)position;
        }
        break;
    case 84:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103517261u + 0x4E89u;
        }
        out[(uint32_t)(index + 84) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        __attribute__((fallthrough));
    case 85:
        acc = acc * 1103517285u + 0xC83Au;
        __attribute__((fallthrough));
    case 86:
        acc ^= 0x41EBu;
        acc = (acc << 25u) | (acc >> 7u);
        __attribute__((fallthrough));
    case 87:
        if ((acc & 0x00008000u) != 0u) { acc += 0xBB9Cu; }
        else { acc ^= 1103517333u; }
        break;
    case 88:
        for (position = 0; position < 3; ++position) {
            acc = acc * 1103517357u + (uint32_t)position;
        }
        __attribute__((fallthrough));
    case 89:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103517381u + 0xAEFEu;
        }
        out[(uint32_t)(index + 89) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        __attribute__((fallthrough));
    case 90:
        acc = acc * 1103517405u + 0x28AFu;
        __attribute__((fallthrough));
    case 91:
        acc ^= 0xA260u;
        acc = (acc << 30u) | (acc >> 2u);
        break;
    case 92:
        if ((acc & 0x00100000u) != 0u) { acc += 0x1C11u; }
        else { acc ^= 1103517453u; }
        __attribute__((fallthrough));
    case 93:
        for (position = 0; position < 2; ++position) {
            acc = acc * 1103517477u + (uint32_t)position;
        }
        __attribute__((fallthrough));
    case 94:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103517501u + 0x0F73u;
        }
        out[(uint32_t)(index + 94) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        __attribute__((fallthrough));
    case 95:
        acc = acc * 1103517525u + 0x8924u;
        break;
    case 96:
        acc ^= 0x02D5u;
        acc = (acc << 4u) | (acc >> 28u);
        __attribute__((fallthrough));
    case 97:
        if ((acc & 0x00000002u) != 0u) { acc += 0x7C86u; }
        else { acc ^= 1103517573u; }
        __attribute__((fallthrough));
    case 98:
        for (position = 0; position < 4; ++position) {
            acc = acc * 1103517597u + (uint32_t)position;
        }
        __attribute__((fallthrough));
    case 99:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103517621u + 0x6FE8u;
        }
        out[(uint32_t)(index + 99) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        break;
    case 100:
        acc = acc * 1103517645u + 0xE999u;
        __attribute__((fallthrough));
    case 101:
        acc ^= 0x634Au;
        acc = (acc << 9u) | (acc >> 23u);
        __attribute__((fallthrough));
    case 102:
        if ((acc & 0x00000040u) != 0u) { acc += 0xDCFBu; }
        else { acc ^= 1103517693u; }
        __attribute__((fallthrough));
    case 103:
        for (position = 0; position < 3; ++position) {
            acc = acc * 1103517717u + (uint32_t)position;
        }
        break;
    case 104:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103517741u + 0xD05Du;
        }
        out[(uint32_t)(index + 104) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        __attribute__((fallthrough));
    case 105:
        acc = acc * 1103517765u + 0x4A0Eu;
        __attribute__((fallthrough));
    case 106:
        acc ^= 0xC3BFu;
        acc = (acc << 14u) | (acc >> 18u);
        __attribute__((fallthrough));
    case 107:
        if ((acc & 0x00000800u) != 0u) { acc += 0x3D70u; }
        else { acc ^= 1103517813u; }
        break;
    case 108:
        for (position = 0; position < 2; ++position) {
            acc = acc * 1103517837u + (uint32_t)position;
        }
        __attribute__((fallthrough));
    case 109:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103517861u + 0x30D2u;
        }
        out[(uint32_t)(index + 109) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        __attribute__((fallthrough));
    case 110:
        acc = acc * 1103517885u + 0xAA83u;
        __attribute__((fallthrough));
    case 111:
        acc ^= 0x2434u;
        acc = (acc << 19u) | (acc >> 13u);
        break;
    case 112:
        if ((acc & 0x00010000u) != 0u) { acc += 0x9DE5u; }
        else { acc ^= 1103517933u; }
        __attribute__((fallthrough));
    case 113:
        for (position = 0; position < 4; ++position) {
            acc = acc * 1103517957u + (uint32_t)position;
        }
        __attribute__((fallthrough));
    case 114:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103517981u + 0x9147u;
        }
        out[(uint32_t)(index + 114) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        __attribute__((fallthrough));
    case 115:
        acc = acc * 1103518005u + 0x0AF8u;
        break;
    case 116:
        acc ^= 0x84A9u;
        acc = (acc << 24u) | (acc >> 8u);
        __attribute__((fallthrough));
    case 117:
        if ((acc & 0x00200000u) != 0u) { acc += 0xFE5Au; }
        else { acc ^= 1103518053u; }
        __attribute__((fallthrough));
    case 118:
        for (position = 0; position < 3; ++position) {
            acc = acc * 1103518077u + (uint32_t)position;
        }
        __attribute__((fallthrough));
    case 119:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103518101u + 0xF1BCu;
        }
        out[(uint32_t)(index + 119) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        break;
    case 120:
        acc = acc * 1103518125u + 0x6B6Du;
        __attribute__((fallthrough));
    case 121:
        acc ^= 0xE51Eu;
        acc = (acc << 29u) | (acc >> 3u);
        __attribute__((fallthrough));
    case 122:
        if ((acc & 0x00000004u) != 0u) { acc += 0x5ECFu; }
        else { acc ^= 1103518173u; }
        __attribute__((fallthrough));
    case 123:
        for (position = 0; position < 2; ++position) {
            acc = acc * 1103518197u + (uint32_t)position;
        }
        break;
    case 124:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103518221u + 0x5231u;
        }
        out[(uint32_t)(index + 124) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        __attribute__((fallthrough));
    case 125:
        acc = acc * 1103518245u + 0xCBE2u;
        __attribute__((fallthrough));
    case 126:
        acc ^= 0x4593u;
        acc = (acc << 3u) | (acc >> 29u);
        __attribute__((fallthrough));
    case 127:
        if ((acc & 0x00000080u) != 0u) { acc += 0xBF44u; }
        else { acc ^= 1103518293u; }
        break;
    case 128:
        for (position = 0; position < 4; ++position) {
            acc = acc * 1103518317u + (uint32_t)position;
        }
        __attribute__((fallthrough));
    case 129:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103518341u + 0xB2A6u;
        }
        out[(uint32_t)(index + 129) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        __attribute__((fallthrough));
    case 130:
        acc = acc * 1103518365u + 0x2C57u;
        __attribute__((fallthrough));
    case 131:
        acc ^= 0xA608u;
        acc = (acc << 8u) | (acc >> 24u);
        break;
    case 132:
        if ((acc & 0x00001000u) != 0u) { acc += 0x1FB9u; }
        else { acc ^= 1103518413u; }
        __attribute__((fallthrough));
    case 133:
        for (position = 0; position < 3; ++position) {
            acc = acc * 1103518437u + (uint32_t)position;
        }
        __attribute__((fallthrough));
    case 134:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103518461u + 0x131Bu;
        }
        out[(uint32_t)(index + 134) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        __attribute__((fallthrough));
    case 135:
        acc = acc * 1103518485u + 0x8CCCu;
        break;
    case 136:
        acc ^= 0x067Du;
        acc = (acc << 13u) | (acc >> 19u);
        __attribute__((fallthrough));
    case 137:
        if ((acc & 0x00020000u) != 0u) { acc += 0x802Eu; }
        else { acc ^= 1103518533u; }
        __attribute__((fallthrough));
    case 138:
        for (position = 0; position < 2; ++position) {
            acc = acc * 1103518557u + (uint32_t)position;
        }
        __attribute__((fallthrough));
    case 139:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103518581u + 0x7390u;
        }
        out[(uint32_t)(index + 139) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        break;
    case 140:
        acc = acc * 1103518605u + 0xED41u;
        __attribute__((fallthrough));
    case 141:
        acc ^= 0x66F2u;
        acc = (acc << 18u) | (acc >> 14u);
        __attribute__((fallthrough));
    case 142:
        if ((acc & 0x00400000u) != 0u) { acc += 0xE0A3u; }
        else { acc ^= 1103518653u; }
        __attribute__((fallthrough));
    case 143:
        for (position = 0; position < 4; ++position) {
            acc = acc * 1103518677u + (uint32_t)position;
        }
        break;
    case 144:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103518701u + 0xD405u;
        }
        out[(uint32_t)(index + 144) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        __attribute__((fallthrough));
    case 145:
        acc = acc * 1103518725u + 0x4DB6u;
        __attribute__((fallthrough));
    case 146:
        acc ^= 0xC767u;
        acc = (acc << 23u) | (acc >> 9u);
        __attribute__((fallthrough));
    case 147:
        if ((acc & 0x00000008u) != 0u) { acc += 0x4118u; }
        else { acc ^= 1103518773u; }
        break;
    case 148:
        for (position = 0; position < 3; ++position) {
            acc = acc * 1103518797u + (uint32_t)position;
        }
        __attribute__((fallthrough));
    case 149:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103518821u + 0x347Au;
        }
        out[(uint32_t)(index + 149) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        __attribute__((fallthrough));
    case 150:
        acc = acc * 1103518845u + 0xAE2Bu;
        __attribute__((fallthrough));
    case 151:
        acc ^= 0x27DCu;
        acc = (acc << 28u) | (acc >> 4u);
        break;
    case 152:
        if ((acc & 0x00000100u) != 0u) { acc += 0xA18Du; }
        else { acc ^= 1103518893u; }
        __attribute__((fallthrough));
    case 153:
        for (position = 0; position < 2; ++position) {
            acc = acc * 1103518917u + (uint32_t)position;
        }
        __attribute__((fallthrough));
    case 154:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103518941u + 0x94EFu;
        }
        out[(uint32_t)(index + 154) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        __attribute__((fallthrough));
    case 155:
        acc = acc * 1103518965u + 0x0EA0u;
        break;
    case 156:
        acc ^= 0x8851u;
        acc = (acc << 2u) | (acc >> 30u);
        __attribute__((fallthrough));
    case 157:
        if ((acc & 0x00002000u) != 0u) { acc += 0x0202u; }
        else { acc ^= 1103519013u; }
        __attribute__((fallthrough));
    case 158:
        for (position = 0; position < 4; ++position) {
            acc = acc * 1103519037u + (uint32_t)position;
        }
        __attribute__((fallthrough));
    case 159:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103519061u + 0xF564u;
        }
        out[(uint32_t)(index + 159) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        break;
    case 160:
        acc = acc * 1103519085u + 0x6F15u;
        __attribute__((fallthrough));
    case 161:
        acc ^= 0xE8C6u;
        acc = (acc << 7u) | (acc >> 25u);
        __attribute__((fallthrough));
    case 162:
        if ((acc & 0x00040000u) != 0u) { acc += 0x6277u; }
        else { acc ^= 1103519133u; }
        __attribute__((fallthrough));
    case 163:
        for (position = 0; position < 3; ++position) {
            acc = acc * 1103519157u + (uint32_t)position;
        }
        break;
    case 164:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103519181u + 0x55D9u;
        }
        out[(uint32_t)(index + 164) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        __attribute__((fallthrough));
    case 165:
        acc = acc * 1103519205u + 0xCF8Au;
        __attribute__((fallthrough));
    case 166:
        acc ^= 0x493Bu;
        acc = (acc << 12u) | (acc >> 20u);
        __attribute__((fallthrough));
    case 167:
        if ((acc & 0x00800000u) != 0u) { acc += 0xC2ECu; }
        else { acc ^= 1103519253u; }
        break;
    case 168:
        for (position = 0; position < 2; ++position) {
            acc = acc * 1103519277u + (uint32_t)position;
        }
        __attribute__((fallthrough));
    case 169:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103519301u + 0xB64Eu;
        }
        out[(uint32_t)(index + 169) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        __attribute__((fallthrough));
    case 170:
        acc = acc * 1103519325u + 0x2FFFu;
        __attribute__((fallthrough));
    case 171:
        acc ^= 0xA9B0u;
        acc = (acc << 17u) | (acc >> 15u);
        break;
    case 172:
        if ((acc & 0x00000010u) != 0u) { acc += 0x2361u; }
        else { acc ^= 1103519373u; }
        __attribute__((fallthrough));
    case 173:
        for (position = 0; position < 4; ++position) {
            acc = acc * 1103519397u + (uint32_t)position;
        }
        __attribute__((fallthrough));
    case 174:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103519421u + 0x16C3u;
        }
        out[(uint32_t)(index + 174) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        __attribute__((fallthrough));
    case 175:
        acc = acc * 1103519445u + 0x9074u;
        break;
    case 176:
        acc ^= 0x0A25u;
        acc = (acc << 22u) | (acc >> 10u);
        __attribute__((fallthrough));
    case 177:
        if ((acc & 0x00000200u) != 0u) { acc += 0x83D6u; }
        else { acc ^= 1103519493u; }
        __attribute__((fallthrough));
    case 178:
        for (position = 0; position < 3; ++position) {
            acc = acc * 1103519517u + (uint32_t)position;
        }
        __attribute__((fallthrough));
    case 179:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103519541u + 0x7738u;
        }
        out[(uint32_t)(index + 179) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        break;
    case 180:
        acc = acc * 1103519565u + 0xF0E9u;
        __attribute__((fallthrough));
    case 181:
        acc ^= 0x6A9Au;
        acc = (acc << 27u) | (acc >> 5u);
        __attribute__((fallthrough));
    case 182:
        if ((acc & 0x00004000u) != 0u) { acc += 0xE44Bu; }
        else { acc ^= 1103519613u; }
        __attribute__((fallthrough));
    case 183:
        for (position = 0; position < 2; ++position) {
            acc = acc * 1103519637u + (uint32_t)position;
        }
        break;
    case 184:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103519661u + 0xD7ADu;
        }
        out[(uint32_t)(index + 184) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        __attribute__((fallthrough));
    case 185:
        acc = acc * 1103519685u + 0x515Eu;
        __attribute__((fallthrough));
    case 186:
        acc ^= 0xCB0Fu;
        acc = (acc << 1u) | (acc >> 31u);
        __attribute__((fallthrough));
    case 187:
        if ((acc & 0x00080000u) != 0u) { acc += 0x44C0u; }
        else { acc ^= 1103519733u; }
        break;
    case 188:
        for (position = 0; position < 4; ++position) {
            acc = acc * 1103519757u + (uint32_t)position;
        }
        __attribute__((fallthrough));
    case 189:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103519781u + 0x3822u;
        }
        out[(uint32_t)(index + 189) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        __attribute__((fallthrough));
    case 190:
        acc = acc * 1103519805u + 0xB1D3u;
        __attribute__((fallthrough));
    case 191:
        acc ^= 0x2B84u;
        acc = (acc << 6u) | (acc >> 26u);
        break;
    case 192:
        if ((acc & 0x00000001u) != 0u) { acc += 0xA535u; }
        else { acc ^= 1103519853u; }
        __attribute__((fallthrough));
    case 193:
        for (position = 0; position < 3; ++position) {
            acc = acc * 1103519877u + (uint32_t)position;
        }
        __attribute__((fallthrough));
    case 194:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103519901u + 0x9897u;
        }
        out[(uint32_t)(index + 194) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        __attribute__((fallthrough));
    case 195:
        acc = acc * 1103519925u + 0x1248u;
        break;
    case 196:
        acc ^= 0x8BF9u;
        acc = (acc << 11u) | (acc >> 21u);
        __attribute__((fallthrough));
    case 197:
        if ((acc & 0x00000020u) != 0u) { acc += 0x05AAu; }
        else { acc ^= 1103519973u; }
        __attribute__((fallthrough));
    case 198:
        for (position = 0; position < 2; ++position) {
            acc = acc * 1103519997u + (uint32_t)position;
        }
        __attribute__((fallthrough));
    case 199:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103520021u + 0xF90Cu;
        }
        out[(uint32_t)(index + 199) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        break;
    case 200:
        acc = acc * 1103520045u + 0x72BDu;
        __attribute__((fallthrough));
    case 201:
        acc ^= 0xEC6Eu;
        acc = (acc << 16u) | (acc >> 16u);
        __attribute__((fallthrough));
    case 202:
        if ((acc & 0x00000400u) != 0u) { acc += 0x661Fu; }
        else { acc ^= 1103520093u; }
        __attribute__((fallthrough));
    case 203:
        for (position = 0; position < 4; ++position) {
            acc = acc * 1103520117u + (uint32_t)position;
        }
        break;
    case 204:
        for (position = 0; position < 3 && (acc & 7u) != 0u; ++position) {
            acc = acc * 1103520141u + 0x5981u;
        }
        out[(uint32_t)(index + 204) % (uint32_t)slots] ^= (int32_t)(acc & 0xFFFFu);
        __attribute__((fallthrough));
    case 205:
        acc = acc * 1103520165u + 0xD332u;
        __attribute__((fallthrough));
    case 206:
        acc ^= 0x4CE3u;
        acc = (acc << 21u) | (acc >> 11u);
        __attribute__((fallthrough));
    case 207:
        if ((acc & 0x00008000u) != 0u) { acc += 0xC694u; }
        else { acc ^= 1103520213u; }
        break;
    default:
        acc ^= 0xFEEDFACEu;
        break;
    }

    out[(uint32_t)index % (uint32_t)slots] = (int32_t)(acc & 0x7FFFFFFFu);
    out[0] = (int32_t)((uint32_t)out[0] ^ (acc >> 16));
    return (int32_t)(acc & 0x0000FFFFu);
}

/* Case k is 7 + k*4099, so the labels run from 7 to 815708 with no two
 * adjacent: no jump table is possible and the lowering is a comparison
 * tree about eight levels deep. */
__attribute__((noinline)) int32_t wide154_sparse_switch(int32_t selector) {
    uint32_t slot = (uint32_t)selector % WIDE154_SPARSE_SPAN;
    int32_t label = (int32_t)(slot * WIDE154_SPARSE_STRIDE + 7u);

    switch (label) {
    case 7: return 20000;
    case 4106: return 19989;
    case 8205: return 19978;
    case 12304: return 19967;
    case 16403: return 19956;
    case 20502: return 19945;
    case 24601: return 19934;
    case 28700: return 19923;
    case 32799: return 19912;
    case 36898: return 19901;
    case 40997: return 19890;
    case 45096: return 19879;
    case 49195: return 19868;
    case 53294: return 19857;
    case 57393: return 19846;
    case 61492: return 19835;
    case 65591: return 19824;
    case 69690: return 19813;
    case 73789: return 19802;
    case 77888: return 19791;
    case 81987: return 19780;
    case 86086: return 19769;
    case 90185: return 19758;
    case 94284: return 19747;
    case 98383: return 19736;
    case 102482: return 19725;
    case 106581: return 19714;
    case 110680: return 19703;
    case 114779: return 19692;
    case 118878: return 19681;
    case 122977: return 19670;
    case 127076: return 19659;
    case 131175: return 19648;
    case 135274: return 19637;
    case 139373: return 19626;
    case 143472: return 19615;
    case 147571: return 19604;
    case 151670: return 19593;
    case 155769: return 19582;
    case 159868: return 19571;
    case 163967: return 19560;
    case 168066: return 19549;
    case 172165: return 19538;
    case 176264: return 19527;
    case 180363: return 19516;
    case 184462: return 19505;
    case 188561: return 19494;
    case 192660: return 19483;
    case 196759: return 19472;
    case 200858: return 19461;
    case 204957: return 19450;
    case 209056: return 19439;
    case 213155: return 19428;
    case 217254: return 19417;
    case 221353: return 19406;
    case 225452: return 19395;
    case 229551: return 19384;
    case 233650: return 19373;
    case 237749: return 19362;
    case 241848: return 19351;
    case 245947: return 19340;
    case 250046: return 19329;
    case 254145: return 19318;
    case 258244: return 19307;
    case 262343: return 19296;
    case 266442: return 19285;
    case 270541: return 19274;
    case 274640: return 19263;
    case 278739: return 19252;
    case 282838: return 19241;
    case 286937: return 19230;
    case 291036: return 19219;
    case 295135: return 19208;
    case 299234: return 19197;
    case 303333: return 19186;
    case 307432: return 19175;
    case 311531: return 19164;
    case 315630: return 19153;
    case 319729: return 19142;
    case 323828: return 19131;
    case 327927: return 19120;
    case 332026: return 19109;
    case 336125: return 19098;
    case 340224: return 19087;
    case 344323: return 19076;
    case 348422: return 19065;
    case 352521: return 19054;
    case 356620: return 19043;
    case 360719: return 19032;
    case 364818: return 19021;
    case 368917: return 19010;
    case 373016: return 18999;
    case 377115: return 18988;
    case 381214: return 18977;
    case 385313: return 18966;
    case 389412: return 18955;
    case 393511: return 18944;
    case 397610: return 18933;
    case 401709: return 18922;
    case 405808: return 18911;
    case 409907: return 18900;
    case 414006: return 18889;
    case 418105: return 18878;
    case 422204: return 18867;
    case 426303: return 18856;
    case 430402: return 18845;
    case 434501: return 18834;
    case 438600: return 18823;
    case 442699: return 18812;
    case 446798: return 18801;
    case 450897: return 18790;
    case 454996: return 18779;
    case 459095: return 18768;
    case 463194: return 18757;
    case 467293: return 18746;
    case 471392: return 18735;
    case 475491: return 18724;
    case 479590: return 18713;
    case 483689: return 18702;
    case 487788: return 18691;
    case 491887: return 18680;
    case 495986: return 18669;
    case 500085: return 18658;
    case 504184: return 18647;
    case 508283: return 18636;
    case 512382: return 18625;
    case 516481: return 18614;
    case 520580: return 18603;
    case 524679: return 18592;
    case 528778: return 18581;
    case 532877: return 18570;
    case 536976: return 18559;
    case 541075: return 18548;
    case 545174: return 18537;
    case 549273: return 18526;
    case 553372: return 18515;
    case 557471: return 18504;
    case 561570: return 18493;
    case 565669: return 18482;
    case 569768: return 18471;
    case 573867: return 18460;
    case 577966: return 18449;
    case 582065: return 18438;
    case 586164: return 18427;
    case 590263: return 18416;
    case 594362: return 18405;
    case 598461: return 18394;
    case 602560: return 18383;
    case 606659: return 18372;
    case 610758: return 18361;
    case 614857: return 18350;
    case 618956: return 18339;
    case 623055: return 18328;
    case 627154: return 18317;
    case 631253: return 18306;
    case 635352: return 18295;
    case 639451: return 18284;
    case 643550: return 18273;
    case 647649: return 18262;
    case 651748: return 18251;
    case 655847: return 18240;
    case 659946: return 18229;
    case 664045: return 18218;
    case 668144: return 18207;
    case 672243: return 18196;
    case 676342: return 18185;
    case 680441: return 18174;
    case 684540: return 18163;
    case 688639: return 18152;
    case 692738: return 18141;
    case 696837: return 18130;
    case 700936: return 18119;
    case 705035: return 18108;
    case 709134: return 18097;
    case 713233: return 18086;
    case 717332: return 18075;
    case 721431: return 18064;
    case 725530: return 18053;
    case 729629: return 18042;
    case 733728: return 18031;
    case 737827: return 18020;
    case 741926: return 18009;
    case 746025: return 17998;
    case 750124: return 17987;
    case 754223: return 17976;
    case 758322: return 17965;
    case 762421: return 17954;
    case 766520: return 17943;
    case 770619: return 17932;
    case 774718: return 17921;
    case 778817: return 17910;
    case 782916: return 17899;
    case 787015: return 17888;
    case 791114: return 17877;
    case 795213: return 17866;
    case 799312: return 17855;
    case 803411: return 17844;
    case 807510: return 17833;
    case 811609: return 17822;
    case 815708: return 17811;
    default: return -1;
    }
}
