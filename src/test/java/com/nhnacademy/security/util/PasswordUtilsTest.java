package com.nhnacademy.security.util;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

public class PasswordUtilsTest {
    @Test
    void test() {
        String password = "12345";

        List<String> hashes = new ArrayList<>();

        for (int i = 0; i < 10; i++) {
            hashes.add(PasswordUtils.simple(password));
        }

        for (int i = 0; i < 10; i++) {
            assertThat(hashes.get(i)).isEqualTo("5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5");
        }

        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[8];

        hashes.clear();

        for (int i = 0; i < 10; i++) {
            random.nextBytes(salt);
            String digest = PasswordUtils.encode(password, salt);

            System.out.println("salt=" + PasswordUtils.bytesToHex(salt) + ", digest=" + digest);
            hashes.add(digest);
        }

        Set<String> set = new HashSet<>(hashes);
        assertThat(set).hasSize(10);
    }

}
