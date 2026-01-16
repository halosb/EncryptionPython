package com.example.encryptionpython.core;

import org.apache.commons.codec.binary.Hex;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class CryptoUtils {
    // Use single-byte XOR key 0x5A to match Python-side obfuscation
    private static final byte[] XOR_KEY = new byte[]{0x5A};

    public static byte[] generateSalt(int len) throws Exception {
        SecureRandom r = new SecureRandom();
        byte[] s = new byte[len];
        r.nextBytes(s);
        return s;
    }

    // simple obfuscation: XOR with key and shift by +3
    public static String obfuscatePassword(String pwd) {
        byte[] bs = pwd.getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[bs.length];
        for (int i = 0; i < bs.length; i++) {
            out[i] = (byte) ((bs[i] ^ XOR_KEY[i % XOR_KEY.length]) + 3);
        }
        return Hex.encodeHexString(out);
    }

    public static String sha256Hex(byte[] salt, String obfuscatedHex) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(salt);
        byte[] ob = Hex.decodeHex(obfuscatedHex.toCharArray());
        md.update(ob);
        byte[] d = md.digest();
        return Hex.encodeHexString(d);
    }

    public static String hex(byte[] b) {
        return Hex.encodeHexString(b);
    }
}
