package com.example.encryptionpython.core;

public class Obfuscator {
    // simple XOR-based runtime string deobfuscation to hide literals in the tool
    public static String decode(String hex, byte key) {
        byte[] bs = hexStringToByteArray(hex);
        for (int i = 0; i < bs.length; i++) bs[i] = (byte) (bs[i] ^ key);
        return new String(bs);
    }

    public static String encodeRaw(String s, byte key) {
        byte[] bs = s.getBytes();
        for (int i = 0; i < bs.length; i++) bs[i] = (byte) (bs[i] ^ key);
        return bytesToHex(bs);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}
