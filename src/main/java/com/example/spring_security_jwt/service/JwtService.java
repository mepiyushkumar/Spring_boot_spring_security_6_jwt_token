package com.example.spring_security_jwt.service;

import com.example.spring_security_jwt.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.MacProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.security.KeyStore;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${jwt.expiry}")
    private int expiry;


    private static final Key secret = MacProvider.generateKey(SignatureAlgorithm.HS256);
    private static final byte[] secretBytes = secret.getEncoded();
    private final String SECRET = Base64.getEncoder().encodeToString(secretBytes);;


    public String generateToken(User user){

        System.out.println("SECRET KEY "+SECRET);


        //payload
        Map<String, Object> claims = new HashMap<>();

        Date expiryDate = new Date(System.currentTimeMillis() + expiry * 1000L);


        return Jwts
                .builder()
                .setClaims(claims)
                .setSubject(user.getUserId())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS256,SECRET)
                .compact();


    }

    public String extractUserId(String token){
        return extractClaims(token, Claims::getSubject);
    }

    public <T> T extractClaims(String token, Function<Claims,T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token){

        Claims claims =
                Jwts.parser()
                        .setSigningKey(SECRET)
                        .parseClaimsJws(token)
                        .getBody();
        return claims;
    }



    public boolean validateToken(String token, UserDetails userDetails) {
        String userIdFetchedFromToken = extractClaims(token,Claims::getSubject);
        return userIdFetchedFromToken.equals(userDetails.getUsername()) && !isTokenExpired(token);

    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaims(token,Claims::getExpiration);

    }
}
