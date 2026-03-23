//! Bitcoin Script opcodes.
//!
//! This module defines all Bitcoin Script opcodes as constants, matching the
//! TypeScript SDK's `OP.ts` for cross-SDK compatibility.

use std::collections::HashMap;
use std::sync::LazyLock;

// Push value
pub const OP_FALSE: u8 = 0x00;
pub const OP_0: u8 = 0x00;

// Direct push data (OP_DATA_1 through OP_DATA_75: push exactly N bytes)
pub const OP_DATA_1: u8 = 0x01;
pub const OP_DATA_2: u8 = 0x02;
pub const OP_DATA_3: u8 = 0x03;
pub const OP_DATA_4: u8 = 0x04;
pub const OP_DATA_5: u8 = 0x05;
pub const OP_DATA_6: u8 = 0x06;
pub const OP_DATA_7: u8 = 0x07;
pub const OP_DATA_8: u8 = 0x08;
pub const OP_DATA_9: u8 = 0x09;
pub const OP_DATA_10: u8 = 0x0a;
pub const OP_DATA_11: u8 = 0x0b;
pub const OP_DATA_12: u8 = 0x0c;
pub const OP_DATA_13: u8 = 0x0d;
pub const OP_DATA_14: u8 = 0x0e;
pub const OP_DATA_15: u8 = 0x0f;
pub const OP_DATA_16: u8 = 0x10;
pub const OP_DATA_17: u8 = 0x11;
pub const OP_DATA_18: u8 = 0x12;
pub const OP_DATA_19: u8 = 0x13;
pub const OP_DATA_20: u8 = 0x14;
pub const OP_DATA_21: u8 = 0x15;
pub const OP_DATA_22: u8 = 0x16;
pub const OP_DATA_23: u8 = 0x17;
pub const OP_DATA_24: u8 = 0x18;
pub const OP_DATA_25: u8 = 0x19;
pub const OP_DATA_26: u8 = 0x1a;
pub const OP_DATA_27: u8 = 0x1b;
pub const OP_DATA_28: u8 = 0x1c;
pub const OP_DATA_29: u8 = 0x1d;
pub const OP_DATA_30: u8 = 0x1e;
pub const OP_DATA_31: u8 = 0x1f;
pub const OP_DATA_32: u8 = 0x20;
pub const OP_DATA_33: u8 = 0x21;
pub const OP_DATA_34: u8 = 0x22;
pub const OP_DATA_35: u8 = 0x23;
pub const OP_DATA_36: u8 = 0x24;
pub const OP_DATA_37: u8 = 0x25;
pub const OP_DATA_38: u8 = 0x26;
pub const OP_DATA_39: u8 = 0x27;
pub const OP_DATA_40: u8 = 0x28;
pub const OP_DATA_41: u8 = 0x29;
pub const OP_DATA_42: u8 = 0x2a;
pub const OP_DATA_43: u8 = 0x2b;
pub const OP_DATA_44: u8 = 0x2c;
pub const OP_DATA_45: u8 = 0x2d;
pub const OP_DATA_46: u8 = 0x2e;
pub const OP_DATA_47: u8 = 0x2f;
pub const OP_DATA_48: u8 = 0x30;
pub const OP_DATA_49: u8 = 0x31;
pub const OP_DATA_50: u8 = 0x32;
pub const OP_DATA_51: u8 = 0x33;
pub const OP_DATA_52: u8 = 0x34;
pub const OP_DATA_53: u8 = 0x35;
pub const OP_DATA_54: u8 = 0x36;
pub const OP_DATA_55: u8 = 0x37;
pub const OP_DATA_56: u8 = 0x38;
pub const OP_DATA_57: u8 = 0x39;
pub const OP_DATA_58: u8 = 0x3a;
pub const OP_DATA_59: u8 = 0x3b;
pub const OP_DATA_60: u8 = 0x3c;
pub const OP_DATA_61: u8 = 0x3d;
pub const OP_DATA_62: u8 = 0x3e;
pub const OP_DATA_63: u8 = 0x3f;
pub const OP_DATA_64: u8 = 0x40;
pub const OP_DATA_65: u8 = 0x41;
pub const OP_DATA_66: u8 = 0x42;
pub const OP_DATA_67: u8 = 0x43;
pub const OP_DATA_68: u8 = 0x44;
pub const OP_DATA_69: u8 = 0x45;
pub const OP_DATA_70: u8 = 0x46;
pub const OP_DATA_71: u8 = 0x47;
pub const OP_DATA_72: u8 = 0x48;
pub const OP_DATA_73: u8 = 0x49;
pub const OP_DATA_74: u8 = 0x4a;
pub const OP_DATA_75: u8 = 0x4b;

pub const OP_PUSHDATA1: u8 = 0x4c;
pub const OP_PUSHDATA2: u8 = 0x4d;
pub const OP_PUSHDATA4: u8 = 0x4e;
pub const OP_1NEGATE: u8 = 0x4f;
pub const OP_RESERVED: u8 = 0x50;
pub const OP_TRUE: u8 = 0x51;
pub const OP_1: u8 = 0x51;
pub const OP_2: u8 = 0x52;
pub const OP_3: u8 = 0x53;
pub const OP_4: u8 = 0x54;
pub const OP_5: u8 = 0x55;
pub const OP_6: u8 = 0x56;
pub const OP_7: u8 = 0x57;
pub const OP_8: u8 = 0x58;
pub const OP_9: u8 = 0x59;
pub const OP_10: u8 = 0x5a;
pub const OP_11: u8 = 0x5b;
pub const OP_12: u8 = 0x5c;
pub const OP_13: u8 = 0x5d;
pub const OP_14: u8 = 0x5e;
pub const OP_15: u8 = 0x5f;
pub const OP_16: u8 = 0x60;

// Control flow
pub const OP_NOP: u8 = 0x61;
pub const OP_VER: u8 = 0x62;
pub const OP_IF: u8 = 0x63;
pub const OP_NOTIF: u8 = 0x64;
pub const OP_VERIF: u8 = 0x65;
pub const OP_VERNOTIF: u8 = 0x66;
pub const OP_ELSE: u8 = 0x67;
pub const OP_ENDIF: u8 = 0x68;
pub const OP_VERIFY: u8 = 0x69;
pub const OP_RETURN: u8 = 0x6a;

// Stack ops
pub const OP_TOALTSTACK: u8 = 0x6b;
pub const OP_FROMALTSTACK: u8 = 0x6c;
pub const OP_2DROP: u8 = 0x6d;
pub const OP_2DUP: u8 = 0x6e;
pub const OP_3DUP: u8 = 0x6f;
pub const OP_2OVER: u8 = 0x70;
pub const OP_2ROT: u8 = 0x71;
pub const OP_2SWAP: u8 = 0x72;
pub const OP_IFDUP: u8 = 0x73;
pub const OP_DEPTH: u8 = 0x74;
pub const OP_DROP: u8 = 0x75;
pub const OP_DUP: u8 = 0x76;
pub const OP_NIP: u8 = 0x77;
pub const OP_OVER: u8 = 0x78;
pub const OP_PICK: u8 = 0x79;
pub const OP_ROLL: u8 = 0x7a;
pub const OP_ROT: u8 = 0x7b;
pub const OP_SWAP: u8 = 0x7c;
pub const OP_TUCK: u8 = 0x7d;

// Data manipulation ops (BSV re-enabled)
pub const OP_CAT: u8 = 0x7e;
pub const OP_SUBSTR: u8 = 0x7f; // Legacy name
pub const OP_SPLIT: u8 = 0x7f; // BSV name
pub const OP_LEFT: u8 = 0x80; // Legacy name
pub const OP_NUM2BIN: u8 = 0x80; // BSV name
pub const OP_RIGHT: u8 = 0x81; // Legacy name
pub const OP_BIN2NUM: u8 = 0x81; // BSV name
pub const OP_SIZE: u8 = 0x82;

// Bit logic
pub const OP_INVERT: u8 = 0x83;
pub const OP_AND: u8 = 0x84;
pub const OP_OR: u8 = 0x85;
pub const OP_XOR: u8 = 0x86;
pub const OP_EQUAL: u8 = 0x87;
pub const OP_EQUALVERIFY: u8 = 0x88;
pub const OP_RESERVED1: u8 = 0x89;
pub const OP_RESERVED2: u8 = 0x8a;

// Numeric ops
pub const OP_1ADD: u8 = 0x8b;
pub const OP_1SUB: u8 = 0x8c;
pub const OP_2MUL: u8 = 0x8d;
pub const OP_2DIV: u8 = 0x8e;
pub const OP_NEGATE: u8 = 0x8f;
pub const OP_ABS: u8 = 0x90;
pub const OP_NOT: u8 = 0x91;
pub const OP_0NOTEQUAL: u8 = 0x92;
pub const OP_ADD: u8 = 0x93;
pub const OP_SUB: u8 = 0x94;
pub const OP_MUL: u8 = 0x95;
pub const OP_DIV: u8 = 0x96;
pub const OP_MOD: u8 = 0x97;
pub const OP_LSHIFT: u8 = 0x98;
pub const OP_RSHIFT: u8 = 0x99;
pub const OP_BOOLAND: u8 = 0x9a;
pub const OP_BOOLOR: u8 = 0x9b;
pub const OP_NUMEQUAL: u8 = 0x9c;
pub const OP_NUMEQUALVERIFY: u8 = 0x9d;
pub const OP_NUMNOTEQUAL: u8 = 0x9e;
pub const OP_LESSTHAN: u8 = 0x9f;
pub const OP_GREATERTHAN: u8 = 0xa0;
pub const OP_LESSTHANOREQUAL: u8 = 0xa1;
pub const OP_GREATERTHANOREQUAL: u8 = 0xa2;
pub const OP_MIN: u8 = 0xa3;
pub const OP_MAX: u8 = 0xa4;
pub const OP_WITHIN: u8 = 0xa5;

// Crypto ops
pub const OP_RIPEMD160: u8 = 0xa6;
pub const OP_SHA1: u8 = 0xa7;
pub const OP_SHA256: u8 = 0xa8;
pub const OP_HASH160: u8 = 0xa9;
pub const OP_HASH256: u8 = 0xaa;
pub const OP_CODESEPARATOR: u8 = 0xab;
pub const OP_CHECKSIG: u8 = 0xac;
pub const OP_CHECKSIGVERIFY: u8 = 0xad;
pub const OP_CHECKMULTISIG: u8 = 0xae;
pub const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;

// Expansion NOPs (OP_NOP1 through OP_NOP77)
pub const OP_NOP1: u8 = 0xb0;
pub const OP_NOP2: u8 = 0xb1;
pub const OP_NOP3: u8 = 0xb2;
pub const OP_NOP4: u8 = 0xb3;
pub const OP_NOP5: u8 = 0xb4;
pub const OP_NOP6: u8 = 0xb5;
pub const OP_NOP7: u8 = 0xb6;
pub const OP_NOP8: u8 = 0xb7;
pub const OP_NOP9: u8 = 0xb8;
pub const OP_NOP10: u8 = 0xb9;
pub const OP_NOP11: u8 = 0xba;
pub const OP_NOP12: u8 = 0xbb;
pub const OP_NOP13: u8 = 0xbc;
pub const OP_NOP14: u8 = 0xbd;
pub const OP_NOP15: u8 = 0xbe;
pub const OP_NOP16: u8 = 0xbf;
pub const OP_NOP17: u8 = 0xc0;
pub const OP_NOP18: u8 = 0xc1;
pub const OP_NOP19: u8 = 0xc2;
pub const OP_NOP20: u8 = 0xc3;
pub const OP_NOP21: u8 = 0xc4;
pub const OP_NOP22: u8 = 0xc5;
pub const OP_NOP23: u8 = 0xc6;
pub const OP_NOP24: u8 = 0xc7;
pub const OP_NOP25: u8 = 0xc8;
pub const OP_NOP26: u8 = 0xc9;
pub const OP_NOP27: u8 = 0xca;
pub const OP_NOP28: u8 = 0xcb;
pub const OP_NOP29: u8 = 0xcc;
pub const OP_NOP30: u8 = 0xcd;
pub const OP_NOP31: u8 = 0xce;
pub const OP_NOP32: u8 = 0xcf;
pub const OP_NOP33: u8 = 0xd0;
pub const OP_NOP34: u8 = 0xd1;
pub const OP_NOP35: u8 = 0xd2;
pub const OP_NOP36: u8 = 0xd3;
pub const OP_NOP37: u8 = 0xd4;
pub const OP_NOP38: u8 = 0xd5;
pub const OP_NOP39: u8 = 0xd6;
pub const OP_NOP40: u8 = 0xd7;
pub const OP_NOP41: u8 = 0xd8;
pub const OP_NOP42: u8 = 0xd9;
pub const OP_NOP43: u8 = 0xda;
pub const OP_NOP44: u8 = 0xdb;
pub const OP_NOP45: u8 = 0xdc;
pub const OP_NOP46: u8 = 0xdd;
pub const OP_NOP47: u8 = 0xde;
pub const OP_NOP48: u8 = 0xdf;
pub const OP_NOP49: u8 = 0xe0;
pub const OP_NOP50: u8 = 0xe1;
pub const OP_NOP51: u8 = 0xe2;
pub const OP_NOP52: u8 = 0xe3;
pub const OP_NOP53: u8 = 0xe4;
pub const OP_NOP54: u8 = 0xe5;
pub const OP_NOP55: u8 = 0xe6;
pub const OP_NOP56: u8 = 0xe7;
pub const OP_NOP57: u8 = 0xe8;
pub const OP_NOP58: u8 = 0xe9;
pub const OP_NOP59: u8 = 0xea;
pub const OP_NOP60: u8 = 0xeb;
pub const OP_NOP61: u8 = 0xec;
pub const OP_NOP62: u8 = 0xed;
pub const OP_NOP63: u8 = 0xee;
pub const OP_NOP64: u8 = 0xef;
pub const OP_NOP65: u8 = 0xf0;
pub const OP_NOP66: u8 = 0xf1;
pub const OP_NOP67: u8 = 0xf2;
pub const OP_NOP68: u8 = 0xf3;
pub const OP_NOP69: u8 = 0xf4;
pub const OP_NOP70: u8 = 0xf5;
pub const OP_NOP71: u8 = 0xf6;
pub const OP_NOP72: u8 = 0xf7;
pub const OP_NOP73: u8 = 0xf8;
pub const OP_NOP77: u8 = 0xfc;

// Template matching params
pub const OP_SMALLDATA: u8 = 0xf9;
pub const OP_SMALLINTEGER: u8 = 0xfa;
pub const OP_PUBKEYS: u8 = 0xfb;
pub const OP_PUBKEYHASH: u8 = 0xfd;
pub const OP_PUBKEY: u8 = 0xfe;

pub const OP_INVALIDOPCODE: u8 = 0xff;

/// Maps opcode names to their values.
static OP_NAME_TO_VALUE: LazyLock<HashMap<&'static str, u8>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    // Push value
    m.insert("OP_FALSE", OP_FALSE);
    m.insert("OP_0", OP_0);

    // Direct push data
    m.insert("OP_DATA_1", OP_DATA_1);
    m.insert("OP_DATA_2", OP_DATA_2);
    m.insert("OP_DATA_3", OP_DATA_3);
    m.insert("OP_DATA_4", OP_DATA_4);
    m.insert("OP_DATA_5", OP_DATA_5);
    m.insert("OP_DATA_6", OP_DATA_6);
    m.insert("OP_DATA_7", OP_DATA_7);
    m.insert("OP_DATA_8", OP_DATA_8);
    m.insert("OP_DATA_9", OP_DATA_9);
    m.insert("OP_DATA_10", OP_DATA_10);
    m.insert("OP_DATA_11", OP_DATA_11);
    m.insert("OP_DATA_12", OP_DATA_12);
    m.insert("OP_DATA_13", OP_DATA_13);
    m.insert("OP_DATA_14", OP_DATA_14);
    m.insert("OP_DATA_15", OP_DATA_15);
    m.insert("OP_DATA_16", OP_DATA_16);
    m.insert("OP_DATA_17", OP_DATA_17);
    m.insert("OP_DATA_18", OP_DATA_18);
    m.insert("OP_DATA_19", OP_DATA_19);
    m.insert("OP_DATA_20", OP_DATA_20);
    m.insert("OP_DATA_21", OP_DATA_21);
    m.insert("OP_DATA_22", OP_DATA_22);
    m.insert("OP_DATA_23", OP_DATA_23);
    m.insert("OP_DATA_24", OP_DATA_24);
    m.insert("OP_DATA_25", OP_DATA_25);
    m.insert("OP_DATA_26", OP_DATA_26);
    m.insert("OP_DATA_27", OP_DATA_27);
    m.insert("OP_DATA_28", OP_DATA_28);
    m.insert("OP_DATA_29", OP_DATA_29);
    m.insert("OP_DATA_30", OP_DATA_30);
    m.insert("OP_DATA_31", OP_DATA_31);
    m.insert("OP_DATA_32", OP_DATA_32);
    m.insert("OP_DATA_33", OP_DATA_33);
    m.insert("OP_DATA_34", OP_DATA_34);
    m.insert("OP_DATA_35", OP_DATA_35);
    m.insert("OP_DATA_36", OP_DATA_36);
    m.insert("OP_DATA_37", OP_DATA_37);
    m.insert("OP_DATA_38", OP_DATA_38);
    m.insert("OP_DATA_39", OP_DATA_39);
    m.insert("OP_DATA_40", OP_DATA_40);
    m.insert("OP_DATA_41", OP_DATA_41);
    m.insert("OP_DATA_42", OP_DATA_42);
    m.insert("OP_DATA_43", OP_DATA_43);
    m.insert("OP_DATA_44", OP_DATA_44);
    m.insert("OP_DATA_45", OP_DATA_45);
    m.insert("OP_DATA_46", OP_DATA_46);
    m.insert("OP_DATA_47", OP_DATA_47);
    m.insert("OP_DATA_48", OP_DATA_48);
    m.insert("OP_DATA_49", OP_DATA_49);
    m.insert("OP_DATA_50", OP_DATA_50);
    m.insert("OP_DATA_51", OP_DATA_51);
    m.insert("OP_DATA_52", OP_DATA_52);
    m.insert("OP_DATA_53", OP_DATA_53);
    m.insert("OP_DATA_54", OP_DATA_54);
    m.insert("OP_DATA_55", OP_DATA_55);
    m.insert("OP_DATA_56", OP_DATA_56);
    m.insert("OP_DATA_57", OP_DATA_57);
    m.insert("OP_DATA_58", OP_DATA_58);
    m.insert("OP_DATA_59", OP_DATA_59);
    m.insert("OP_DATA_60", OP_DATA_60);
    m.insert("OP_DATA_61", OP_DATA_61);
    m.insert("OP_DATA_62", OP_DATA_62);
    m.insert("OP_DATA_63", OP_DATA_63);
    m.insert("OP_DATA_64", OP_DATA_64);
    m.insert("OP_DATA_65", OP_DATA_65);
    m.insert("OP_DATA_66", OP_DATA_66);
    m.insert("OP_DATA_67", OP_DATA_67);
    m.insert("OP_DATA_68", OP_DATA_68);
    m.insert("OP_DATA_69", OP_DATA_69);
    m.insert("OP_DATA_70", OP_DATA_70);
    m.insert("OP_DATA_71", OP_DATA_71);
    m.insert("OP_DATA_72", OP_DATA_72);
    m.insert("OP_DATA_73", OP_DATA_73);
    m.insert("OP_DATA_74", OP_DATA_74);
    m.insert("OP_DATA_75", OP_DATA_75);

    m.insert("OP_PUSHDATA1", OP_PUSHDATA1);
    m.insert("OP_PUSHDATA2", OP_PUSHDATA2);
    m.insert("OP_PUSHDATA4", OP_PUSHDATA4);
    m.insert("OP_1NEGATE", OP_1NEGATE);
    m.insert("OP_RESERVED", OP_RESERVED);
    m.insert("OP_TRUE", OP_TRUE);
    m.insert("OP_1", OP_1);
    m.insert("OP_2", OP_2);
    m.insert("OP_3", OP_3);
    m.insert("OP_4", OP_4);
    m.insert("OP_5", OP_5);
    m.insert("OP_6", OP_6);
    m.insert("OP_7", OP_7);
    m.insert("OP_8", OP_8);
    m.insert("OP_9", OP_9);
    m.insert("OP_10", OP_10);
    m.insert("OP_11", OP_11);
    m.insert("OP_12", OP_12);
    m.insert("OP_13", OP_13);
    m.insert("OP_14", OP_14);
    m.insert("OP_15", OP_15);
    m.insert("OP_16", OP_16);

    // Control flow
    m.insert("OP_NOP", OP_NOP);
    m.insert("OP_VER", OP_VER);
    m.insert("OP_IF", OP_IF);
    m.insert("OP_NOTIF", OP_NOTIF);
    m.insert("OP_VERIF", OP_VERIF);
    m.insert("OP_VERNOTIF", OP_VERNOTIF);
    m.insert("OP_ELSE", OP_ELSE);
    m.insert("OP_ENDIF", OP_ENDIF);
    m.insert("OP_VERIFY", OP_VERIFY);
    m.insert("OP_RETURN", OP_RETURN);

    // Stack ops
    m.insert("OP_TOALTSTACK", OP_TOALTSTACK);
    m.insert("OP_FROMALTSTACK", OP_FROMALTSTACK);
    m.insert("OP_2DROP", OP_2DROP);
    m.insert("OP_2DUP", OP_2DUP);
    m.insert("OP_3DUP", OP_3DUP);
    m.insert("OP_2OVER", OP_2OVER);
    m.insert("OP_2ROT", OP_2ROT);
    m.insert("OP_2SWAP", OP_2SWAP);
    m.insert("OP_IFDUP", OP_IFDUP);
    m.insert("OP_DEPTH", OP_DEPTH);
    m.insert("OP_DROP", OP_DROP);
    m.insert("OP_DUP", OP_DUP);
    m.insert("OP_NIP", OP_NIP);
    m.insert("OP_OVER", OP_OVER);
    m.insert("OP_PICK", OP_PICK);
    m.insert("OP_ROLL", OP_ROLL);
    m.insert("OP_ROT", OP_ROT);
    m.insert("OP_SWAP", OP_SWAP);
    m.insert("OP_TUCK", OP_TUCK);

    // Data manipulation ops
    m.insert("OP_CAT", OP_CAT);
    m.insert("OP_SUBSTR", OP_SUBSTR);
    m.insert("OP_SPLIT", OP_SPLIT);
    m.insert("OP_LEFT", OP_LEFT);
    m.insert("OP_NUM2BIN", OP_NUM2BIN);
    m.insert("OP_RIGHT", OP_RIGHT);
    m.insert("OP_BIN2NUM", OP_BIN2NUM);
    m.insert("OP_SIZE", OP_SIZE);

    // Bit logic
    m.insert("OP_INVERT", OP_INVERT);
    m.insert("OP_AND", OP_AND);
    m.insert("OP_OR", OP_OR);
    m.insert("OP_XOR", OP_XOR);
    m.insert("OP_EQUAL", OP_EQUAL);
    m.insert("OP_EQUALVERIFY", OP_EQUALVERIFY);
    m.insert("OP_RESERVED1", OP_RESERVED1);
    m.insert("OP_RESERVED2", OP_RESERVED2);

    // Numeric ops
    m.insert("OP_1ADD", OP_1ADD);
    m.insert("OP_1SUB", OP_1SUB);
    m.insert("OP_2MUL", OP_2MUL);
    m.insert("OP_2DIV", OP_2DIV);
    m.insert("OP_NEGATE", OP_NEGATE);
    m.insert("OP_ABS", OP_ABS);
    m.insert("OP_NOT", OP_NOT);
    m.insert("OP_0NOTEQUAL", OP_0NOTEQUAL);
    m.insert("OP_ADD", OP_ADD);
    m.insert("OP_SUB", OP_SUB);
    m.insert("OP_MUL", OP_MUL);
    m.insert("OP_DIV", OP_DIV);
    m.insert("OP_MOD", OP_MOD);
    m.insert("OP_LSHIFT", OP_LSHIFT);
    m.insert("OP_RSHIFT", OP_RSHIFT);
    m.insert("OP_BOOLAND", OP_BOOLAND);
    m.insert("OP_BOOLOR", OP_BOOLOR);
    m.insert("OP_NUMEQUAL", OP_NUMEQUAL);
    m.insert("OP_NUMEQUALVERIFY", OP_NUMEQUALVERIFY);
    m.insert("OP_NUMNOTEQUAL", OP_NUMNOTEQUAL);
    m.insert("OP_LESSTHAN", OP_LESSTHAN);
    m.insert("OP_GREATERTHAN", OP_GREATERTHAN);
    m.insert("OP_LESSTHANOREQUAL", OP_LESSTHANOREQUAL);
    m.insert("OP_GREATERTHANOREQUAL", OP_GREATERTHANOREQUAL);
    m.insert("OP_MIN", OP_MIN);
    m.insert("OP_MAX", OP_MAX);
    m.insert("OP_WITHIN", OP_WITHIN);

    // Crypto ops
    m.insert("OP_RIPEMD160", OP_RIPEMD160);
    m.insert("OP_SHA1", OP_SHA1);
    m.insert("OP_SHA256", OP_SHA256);
    m.insert("OP_HASH160", OP_HASH160);
    m.insert("OP_HASH256", OP_HASH256);
    m.insert("OP_CODESEPARATOR", OP_CODESEPARATOR);
    m.insert("OP_CHECKSIG", OP_CHECKSIG);
    m.insert("OP_CHECKSIGVERIFY", OP_CHECKSIGVERIFY);
    m.insert("OP_CHECKMULTISIG", OP_CHECKMULTISIG);
    m.insert("OP_CHECKMULTISIGVERIFY", OP_CHECKMULTISIGVERIFY);

    // NOPs
    m.insert("OP_NOP1", OP_NOP1);
    m.insert("OP_NOP2", OP_NOP2);
    m.insert("OP_NOP3", OP_NOP3);
    m.insert("OP_NOP4", OP_NOP4);
    m.insert("OP_NOP5", OP_NOP5);
    m.insert("OP_NOP6", OP_NOP6);
    m.insert("OP_NOP7", OP_NOP7);
    m.insert("OP_NOP8", OP_NOP8);
    m.insert("OP_NOP9", OP_NOP9);
    m.insert("OP_NOP10", OP_NOP10);
    m.insert("OP_NOP11", OP_NOP11);
    m.insert("OP_NOP12", OP_NOP12);
    m.insert("OP_NOP13", OP_NOP13);
    m.insert("OP_NOP14", OP_NOP14);
    m.insert("OP_NOP15", OP_NOP15);
    m.insert("OP_NOP16", OP_NOP16);
    m.insert("OP_NOP17", OP_NOP17);
    m.insert("OP_NOP18", OP_NOP18);
    m.insert("OP_NOP19", OP_NOP19);
    m.insert("OP_NOP20", OP_NOP20);
    m.insert("OP_NOP21", OP_NOP21);
    m.insert("OP_NOP22", OP_NOP22);
    m.insert("OP_NOP23", OP_NOP23);
    m.insert("OP_NOP24", OP_NOP24);
    m.insert("OP_NOP25", OP_NOP25);
    m.insert("OP_NOP26", OP_NOP26);
    m.insert("OP_NOP27", OP_NOP27);
    m.insert("OP_NOP28", OP_NOP28);
    m.insert("OP_NOP29", OP_NOP29);
    m.insert("OP_NOP30", OP_NOP30);
    m.insert("OP_NOP31", OP_NOP31);
    m.insert("OP_NOP32", OP_NOP32);
    m.insert("OP_NOP33", OP_NOP33);
    m.insert("OP_NOP34", OP_NOP34);
    m.insert("OP_NOP35", OP_NOP35);
    m.insert("OP_NOP36", OP_NOP36);
    m.insert("OP_NOP37", OP_NOP37);
    m.insert("OP_NOP38", OP_NOP38);
    m.insert("OP_NOP39", OP_NOP39);
    m.insert("OP_NOP40", OP_NOP40);
    m.insert("OP_NOP41", OP_NOP41);
    m.insert("OP_NOP42", OP_NOP42);
    m.insert("OP_NOP43", OP_NOP43);
    m.insert("OP_NOP44", OP_NOP44);
    m.insert("OP_NOP45", OP_NOP45);
    m.insert("OP_NOP46", OP_NOP46);
    m.insert("OP_NOP47", OP_NOP47);
    m.insert("OP_NOP48", OP_NOP48);
    m.insert("OP_NOP49", OP_NOP49);
    m.insert("OP_NOP50", OP_NOP50);
    m.insert("OP_NOP51", OP_NOP51);
    m.insert("OP_NOP52", OP_NOP52);
    m.insert("OP_NOP53", OP_NOP53);
    m.insert("OP_NOP54", OP_NOP54);
    m.insert("OP_NOP55", OP_NOP55);
    m.insert("OP_NOP56", OP_NOP56);
    m.insert("OP_NOP57", OP_NOP57);
    m.insert("OP_NOP58", OP_NOP58);
    m.insert("OP_NOP59", OP_NOP59);
    m.insert("OP_NOP60", OP_NOP60);
    m.insert("OP_NOP61", OP_NOP61);
    m.insert("OP_NOP62", OP_NOP62);
    m.insert("OP_NOP63", OP_NOP63);
    m.insert("OP_NOP64", OP_NOP64);
    m.insert("OP_NOP65", OP_NOP65);
    m.insert("OP_NOP66", OP_NOP66);
    m.insert("OP_NOP67", OP_NOP67);
    m.insert("OP_NOP68", OP_NOP68);
    m.insert("OP_NOP69", OP_NOP69);
    m.insert("OP_NOP70", OP_NOP70);
    m.insert("OP_NOP71", OP_NOP71);
    m.insert("OP_NOP72", OP_NOP72);
    m.insert("OP_NOP73", OP_NOP73);
    m.insert("OP_NOP77", OP_NOP77);

    // Template matching
    m.insert("OP_SMALLDATA", OP_SMALLDATA);
    m.insert("OP_SMALLINTEGER", OP_SMALLINTEGER);
    m.insert("OP_PUBKEYS", OP_PUBKEYS);
    m.insert("OP_PUBKEYHASH", OP_PUBKEYHASH);
    m.insert("OP_PUBKEY", OP_PUBKEY);
    m.insert("OP_INVALIDOPCODE", OP_INVALIDOPCODE);

    m
});

/// Maps opcode values to their names.
static OP_VALUE_TO_NAME: LazyLock<HashMap<u8, &'static str>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    m.insert(OP_FALSE, "OP_0");
    m.insert(OP_PUSHDATA1, "OP_PUSHDATA1");
    m.insert(OP_PUSHDATA2, "OP_PUSHDATA2");
    m.insert(OP_PUSHDATA4, "OP_PUSHDATA4");
    m.insert(OP_1NEGATE, "OP_1NEGATE");
    m.insert(OP_RESERVED, "OP_RESERVED");
    m.insert(OP_1, "OP_1");
    m.insert(OP_2, "OP_2");
    m.insert(OP_3, "OP_3");
    m.insert(OP_4, "OP_4");
    m.insert(OP_5, "OP_5");
    m.insert(OP_6, "OP_6");
    m.insert(OP_7, "OP_7");
    m.insert(OP_8, "OP_8");
    m.insert(OP_9, "OP_9");
    m.insert(OP_10, "OP_10");
    m.insert(OP_11, "OP_11");
    m.insert(OP_12, "OP_12");
    m.insert(OP_13, "OP_13");
    m.insert(OP_14, "OP_14");
    m.insert(OP_15, "OP_15");
    m.insert(OP_16, "OP_16");

    // Control flow
    m.insert(OP_NOP, "OP_NOP");
    m.insert(OP_VER, "OP_VER");
    m.insert(OP_IF, "OP_IF");
    m.insert(OP_NOTIF, "OP_NOTIF");
    m.insert(OP_VERIF, "OP_VERIF");
    m.insert(OP_VERNOTIF, "OP_VERNOTIF");
    m.insert(OP_ELSE, "OP_ELSE");
    m.insert(OP_ENDIF, "OP_ENDIF");
    m.insert(OP_VERIFY, "OP_VERIFY");
    m.insert(OP_RETURN, "OP_RETURN");

    // Stack ops
    m.insert(OP_TOALTSTACK, "OP_TOALTSTACK");
    m.insert(OP_FROMALTSTACK, "OP_FROMALTSTACK");
    m.insert(OP_2DROP, "OP_2DROP");
    m.insert(OP_2DUP, "OP_2DUP");
    m.insert(OP_3DUP, "OP_3DUP");
    m.insert(OP_2OVER, "OP_2OVER");
    m.insert(OP_2ROT, "OP_2ROT");
    m.insert(OP_2SWAP, "OP_2SWAP");
    m.insert(OP_IFDUP, "OP_IFDUP");
    m.insert(OP_DEPTH, "OP_DEPTH");
    m.insert(OP_DROP, "OP_DROP");
    m.insert(OP_DUP, "OP_DUP");
    m.insert(OP_NIP, "OP_NIP");
    m.insert(OP_OVER, "OP_OVER");
    m.insert(OP_PICK, "OP_PICK");
    m.insert(OP_ROLL, "OP_ROLL");
    m.insert(OP_ROT, "OP_ROT");
    m.insert(OP_SWAP, "OP_SWAP");
    m.insert(OP_TUCK, "OP_TUCK");

    // Data manipulation ops (use BSV names)
    m.insert(OP_CAT, "OP_CAT");
    m.insert(OP_SPLIT, "OP_SPLIT");
    m.insert(OP_NUM2BIN, "OP_NUM2BIN");
    m.insert(OP_BIN2NUM, "OP_BIN2NUM");
    m.insert(OP_SIZE, "OP_SIZE");

    // Bit logic
    m.insert(OP_INVERT, "OP_INVERT");
    m.insert(OP_AND, "OP_AND");
    m.insert(OP_OR, "OP_OR");
    m.insert(OP_XOR, "OP_XOR");
    m.insert(OP_EQUAL, "OP_EQUAL");
    m.insert(OP_EQUALVERIFY, "OP_EQUALVERIFY");
    m.insert(OP_RESERVED1, "OP_RESERVED1");
    m.insert(OP_RESERVED2, "OP_RESERVED2");

    // Numeric ops
    m.insert(OP_1ADD, "OP_1ADD");
    m.insert(OP_1SUB, "OP_1SUB");
    m.insert(OP_2MUL, "OP_2MUL");
    m.insert(OP_2DIV, "OP_2DIV");
    m.insert(OP_NEGATE, "OP_NEGATE");
    m.insert(OP_ABS, "OP_ABS");
    m.insert(OP_NOT, "OP_NOT");
    m.insert(OP_0NOTEQUAL, "OP_0NOTEQUAL");
    m.insert(OP_ADD, "OP_ADD");
    m.insert(OP_SUB, "OP_SUB");
    m.insert(OP_MUL, "OP_MUL");
    m.insert(OP_DIV, "OP_DIV");
    m.insert(OP_MOD, "OP_MOD");
    m.insert(OP_LSHIFT, "OP_LSHIFT");
    m.insert(OP_RSHIFT, "OP_RSHIFT");
    m.insert(OP_BOOLAND, "OP_BOOLAND");
    m.insert(OP_BOOLOR, "OP_BOOLOR");
    m.insert(OP_NUMEQUAL, "OP_NUMEQUAL");
    m.insert(OP_NUMEQUALVERIFY, "OP_NUMEQUALVERIFY");
    m.insert(OP_NUMNOTEQUAL, "OP_NUMNOTEQUAL");
    m.insert(OP_LESSTHAN, "OP_LESSTHAN");
    m.insert(OP_GREATERTHAN, "OP_GREATERTHAN");
    m.insert(OP_LESSTHANOREQUAL, "OP_LESSTHANOREQUAL");
    m.insert(OP_GREATERTHANOREQUAL, "OP_GREATERTHANOREQUAL");
    m.insert(OP_MIN, "OP_MIN");
    m.insert(OP_MAX, "OP_MAX");
    m.insert(OP_WITHIN, "OP_WITHIN");

    // Crypto ops
    m.insert(OP_RIPEMD160, "OP_RIPEMD160");
    m.insert(OP_SHA1, "OP_SHA1");
    m.insert(OP_SHA256, "OP_SHA256");
    m.insert(OP_HASH160, "OP_HASH160");
    m.insert(OP_HASH256, "OP_HASH256");
    m.insert(OP_CODESEPARATOR, "OP_CODESEPARATOR");
    m.insert(OP_CHECKSIG, "OP_CHECKSIG");
    m.insert(OP_CHECKSIGVERIFY, "OP_CHECKSIGVERIFY");
    m.insert(OP_CHECKMULTISIG, "OP_CHECKMULTISIG");
    m.insert(OP_CHECKMULTISIGVERIFY, "OP_CHECKMULTISIGVERIFY");

    // NOPs
    m.insert(OP_NOP1, "OP_NOP1");
    m.insert(OP_NOP2, "OP_NOP2");
    m.insert(OP_NOP3, "OP_NOP3");
    m.insert(OP_NOP4, "OP_NOP4");
    m.insert(OP_NOP5, "OP_NOP5");
    m.insert(OP_NOP6, "OP_NOP6");
    m.insert(OP_NOP7, "OP_NOP7");
    m.insert(OP_NOP8, "OP_NOP8");
    m.insert(OP_NOP9, "OP_NOP9");
    m.insert(OP_NOP10, "OP_NOP10");
    m.insert(OP_NOP11, "OP_NOP11");
    m.insert(OP_NOP12, "OP_NOP12");
    m.insert(OP_NOP13, "OP_NOP13");
    m.insert(OP_NOP14, "OP_NOP14");
    m.insert(OP_NOP15, "OP_NOP15");
    m.insert(OP_NOP16, "OP_NOP16");
    m.insert(OP_NOP17, "OP_NOP17");
    m.insert(OP_NOP18, "OP_NOP18");
    m.insert(OP_NOP19, "OP_NOP19");
    m.insert(OP_NOP20, "OP_NOP20");
    m.insert(OP_NOP21, "OP_NOP21");
    m.insert(OP_NOP22, "OP_NOP22");
    m.insert(OP_NOP23, "OP_NOP23");
    m.insert(OP_NOP24, "OP_NOP24");
    m.insert(OP_NOP25, "OP_NOP25");
    m.insert(OP_NOP26, "OP_NOP26");
    m.insert(OP_NOP27, "OP_NOP27");
    m.insert(OP_NOP28, "OP_NOP28");
    m.insert(OP_NOP29, "OP_NOP29");
    m.insert(OP_NOP30, "OP_NOP30");
    m.insert(OP_NOP31, "OP_NOP31");
    m.insert(OP_NOP32, "OP_NOP32");
    m.insert(OP_NOP33, "OP_NOP33");
    m.insert(OP_NOP34, "OP_NOP34");
    m.insert(OP_NOP35, "OP_NOP35");
    m.insert(OP_NOP36, "OP_NOP36");
    m.insert(OP_NOP37, "OP_NOP37");
    m.insert(OP_NOP38, "OP_NOP38");
    m.insert(OP_NOP39, "OP_NOP39");
    m.insert(OP_NOP40, "OP_NOP40");
    m.insert(OP_NOP41, "OP_NOP41");
    m.insert(OP_NOP42, "OP_NOP42");
    m.insert(OP_NOP43, "OP_NOP43");
    m.insert(OP_NOP44, "OP_NOP44");
    m.insert(OP_NOP45, "OP_NOP45");
    m.insert(OP_NOP46, "OP_NOP46");
    m.insert(OP_NOP47, "OP_NOP47");
    m.insert(OP_NOP48, "OP_NOP48");
    m.insert(OP_NOP49, "OP_NOP49");
    m.insert(OP_NOP50, "OP_NOP50");
    m.insert(OP_NOP51, "OP_NOP51");
    m.insert(OP_NOP52, "OP_NOP52");
    m.insert(OP_NOP53, "OP_NOP53");
    m.insert(OP_NOP54, "OP_NOP54");
    m.insert(OP_NOP55, "OP_NOP55");
    m.insert(OP_NOP56, "OP_NOP56");
    m.insert(OP_NOP57, "OP_NOP57");
    m.insert(OP_NOP58, "OP_NOP58");
    m.insert(OP_NOP59, "OP_NOP59");
    m.insert(OP_NOP60, "OP_NOP60");
    m.insert(OP_NOP61, "OP_NOP61");
    m.insert(OP_NOP62, "OP_NOP62");
    m.insert(OP_NOP63, "OP_NOP63");
    m.insert(OP_NOP64, "OP_NOP64");
    m.insert(OP_NOP65, "OP_NOP65");
    m.insert(OP_NOP66, "OP_NOP66");
    m.insert(OP_NOP67, "OP_NOP67");
    m.insert(OP_NOP68, "OP_NOP68");
    m.insert(OP_NOP69, "OP_NOP69");
    m.insert(OP_NOP70, "OP_NOP70");
    m.insert(OP_NOP71, "OP_NOP71");
    m.insert(OP_NOP72, "OP_NOP72");
    m.insert(OP_NOP73, "OP_NOP73");
    m.insert(OP_NOP77, "OP_NOP77");

    // Template matching
    m.insert(OP_SMALLDATA, "OP_SMALLDATA");
    m.insert(OP_SMALLINTEGER, "OP_SMALLINTEGER");
    m.insert(OP_PUBKEYS, "OP_PUBKEYS");
    m.insert(OP_PUBKEYHASH, "OP_PUBKEYHASH");
    m.insert(OP_PUBKEY, "OP_PUBKEY");
    m.insert(OP_INVALIDOPCODE, "OP_INVALIDOPCODE");

    m
});

/// Converts an opcode name (e.g., "OP_DUP") to its numeric value.
pub fn name_to_opcode(name: &str) -> Option<u8> {
    OP_NAME_TO_VALUE.get(name).copied()
}

/// Converts an opcode value to its name (e.g., 0x76 -> "OP_DUP").
pub fn opcode_to_name(op: u8) -> Option<&'static str> {
    OP_VALUE_TO_NAME.get(&op).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_values() {
        assert_eq!(OP_FALSE, 0x00);
        assert_eq!(OP_0, 0x00);
        assert_eq!(OP_TRUE, 0x51);
        assert_eq!(OP_1, 0x51);
        assert_eq!(OP_16, 0x60);
        assert_eq!(OP_DUP, 0x76);
        assert_eq!(OP_HASH160, 0xa9);
        assert_eq!(OP_CHECKSIG, 0xac);
        assert_eq!(OP_RETURN, 0x6a);
        assert_eq!(OP_EQUAL, 0x87);
        assert_eq!(OP_EQUALVERIFY, 0x88);
    }

    #[test]
    fn test_name_to_opcode() {
        assert_eq!(name_to_opcode("OP_DUP"), Some(0x76));
        assert_eq!(name_to_opcode("OP_HASH160"), Some(0xa9));
        assert_eq!(name_to_opcode("OP_CHECKSIG"), Some(0xac));
        assert_eq!(name_to_opcode("OP_0"), Some(0x00));
        assert_eq!(name_to_opcode("OP_FALSE"), Some(0x00));
        assert_eq!(name_to_opcode("OP_1"), Some(0x51));
        assert_eq!(name_to_opcode("OP_TRUE"), Some(0x51));
        assert_eq!(name_to_opcode("INVALID"), None);
    }

    #[test]
    fn test_opcode_to_name() {
        assert_eq!(opcode_to_name(0x76), Some("OP_DUP"));
        assert_eq!(opcode_to_name(0xa9), Some("OP_HASH160"));
        assert_eq!(opcode_to_name(0xac), Some("OP_CHECKSIG"));
        assert_eq!(opcode_to_name(0x00), Some("OP_0"));
        assert_eq!(opcode_to_name(0x51), Some("OP_1"));
    }

    #[test]
    fn test_bsv_opcodes() {
        // BSV re-enabled opcodes
        assert_eq!(OP_CAT, 0x7e);
        assert_eq!(OP_SPLIT, 0x7f);
        assert_eq!(OP_NUM2BIN, 0x80);
        assert_eq!(OP_BIN2NUM, 0x81);
        assert_eq!(OP_MUL, 0x95);
        assert_eq!(OP_DIV, 0x96);
        assert_eq!(OP_MOD, 0x97);
    }

    #[test]
    fn test_op_data_constants() {
        // Boundary values
        assert_eq!(OP_DATA_1, 0x01);
        assert_eq!(OP_DATA_75, 0x4b);

        // Verify they don't collide with PUSHDATA opcodes
        const { assert!(OP_DATA_75 < OP_PUSHDATA1) };

        // Name lookups work
        assert_eq!(name_to_opcode("OP_DATA_1"), Some(0x01));
        assert_eq!(name_to_opcode("OP_DATA_75"), Some(0x4b));
        assert_eq!(name_to_opcode("OP_DATA_33"), Some(0x21));
    }
}
