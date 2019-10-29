package com.briller.utility;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

@Component
public class TokenUtility {


    @Value("${briller.jwt.token.secret}")
    private String secret;

    /**
     * This method used to get username from token
     * @param token
     * @return
     */
    public String getUsernameFromToken(String token) {
        String username;
        try {
            username = Jwts.parser()
                    .setSigningKey(secret)
                    .parseClaimsJws(token)
                    .getBody()
                    .getSubject();
        } catch (Exception e) {
            username = null;
        }
        return username;
    }

    /**
     * This method used to generate the token
     * @param userDetails
     * @return String token
     */
    public String generateToken(UserDetails userDetails) {
        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();
    }

    /**
     * This method used to validate the token
     * @param token
     * @param userDetails
     * @return
     */
    public boolean validateToken(String token, UserDetails userDetails) {
        return (getUsernameFromToken(token).equals(userDetails.getUsername()));
    }

    /**
     * This method is used to generate the phone verification token
     * @return token String
     */
    public String generatePhoneToken() {

        SecureRandom random = null;
        try {
            random = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        int token = random.nextInt(100000);

        return String.valueOf(token);
    }

}
