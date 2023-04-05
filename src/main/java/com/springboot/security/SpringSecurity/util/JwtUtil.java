package com.springboot.security.SpringSecurity.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.concurrent.TimeUnit;

@Component
public class JwtUtil {

    @Value("${app.secret}")
    private String secret;

    //6. validate username in token and database, expDate
    public boolean validateToken(String token,String username){
        String tokenUserName =  getUsername(token);
        return (username.equals(tokenUserName) && !isTokenExp(token));
    }



    //5. Validate exp date
    public boolean isTokenExp(String token){
        Date expDate = getExpDate(token);
        return expDate.before(new Date(System.currentTimeMillis()));
    }

    //4. read subject/username
    public String getUsername(String token)
    {
        return getClaims(token).getSubject();
    }

    //3.0Read Read Exp date
    public Date getExpDate(String token){
        return getClaims(token).getExpiration();
    }


    //2. read claims
    public Claims getClaims(String token){
        return Jwts.parser()
                .setSigningKey(secret.getBytes())
                .parseClaimsJws(token)
                .getBody();
    }

    public String generateToken(String subject){
        return Jwts.builder()
                .setSubject(subject)
                .setIssuer("avinash")
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(15)))
                .signWith(SignatureAlgorithm.HS512,secret)
                .compact();
    }

}
