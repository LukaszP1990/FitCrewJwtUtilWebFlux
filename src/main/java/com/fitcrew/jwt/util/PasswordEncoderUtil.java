package com.fitcrew.jwt.util;

import com.fitcrew.FitCrewAppModel.domain.model.AbstractModel;
import io.vavr.control.Try;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

@Component
public class PasswordEncoderUtil implements PasswordEncoder {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA512";

    @Value("${password.encoder.secret}")
    private String secret;

    @Value("${password.encoder.iteration}")
    private Integer iteration;

    @Value("${password.encoder.keylength}")
    private Integer keyLength;

    @Override
    public String encode(CharSequence charSequence) {
        return Try.of(() -> getBytes(charSequence))
                .map(bytes -> Base64.getEncoder().encodeToString(bytes))
                .getOrElse(new RuntimeException().getMessage());
    }

    @Override
    public boolean matches(CharSequence charSequence,
                           String string) {
        return encode(charSequence).equals(string);
    }

    public <T extends AbstractModel> boolean arePasswordsEqual(String authenticationRequestPassword,
                                                               T model) {
        return arePasswordsEqual(authenticationRequestPassword, model.getEncryptedPassword());
    }

    public boolean arePasswordsEqual(String firstPassword,
                                     String encryptedPassword) {
        return firstPassword.equals(encode(encryptedPassword));
    }

    public boolean arePasswordsEqualByCache(String firstPassword,
                                            String secondPassword) {
        return firstPassword.equals(secondPassword);
    }

    private byte[] getBytes(CharSequence charSequence) throws InvalidKeySpecException, NoSuchAlgorithmException {
        return SecretKeyFactory.getInstance(ALGORITHM)
                .generateSecret(
                        getKeySpec(charSequence))
                .getEncoded();
    }

    private PBEKeySpec getKeySpec(CharSequence charSequence) {
        return new PBEKeySpec(
                charSequence.toString().toCharArray(),
                secret.getBytes(),
                iteration,
                keyLength);
    }
}
