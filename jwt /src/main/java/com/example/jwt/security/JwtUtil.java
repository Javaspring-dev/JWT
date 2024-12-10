package com.example.jwt.security;

import com.example.jwt.entity.Role;
import com.example.jwt.entity.User;
import com.example.jwt.repository.UserRepository;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;

import java.util.Date;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class JwtUtil {
    //secretkey
    private static final SecretKey secretkey= Keys.secretKeyFor(SignatureAlgorithm.HS512);
    //expirtion time
     private final int jwtExpirationMs=86400000;

     private UserRepository userRepository;

     public JwtUtil(UserRepository userRepository){
         this.userRepository=userRepository;
     }

     //Generate token
    public String generateToken(String username) {
        Optional<User> user = userRepository.findByUsername((username));
        Set<Role> roles = user.get().getRoles();

        //ADD roles to the token
        return Jwts.builder().setSubject(username).claim("roles", roles.stream()
                        .map(role -> role.getName()).collect(Collectors.joining(",")))
                .setIssuedAt(new Date()).setExpiration(new Date(new Date().getTime() + jwtExpirationMs))
                .signWith(secretkey).compact();


    }
    //Extract Username
    public String extractUsername(String token){
         return Jwts.parserBuilder().setSigningKey(secretkey).build().parseClaimsJws(token).getBody().getSubject();
    }
    //Extract roles

    public Set<String>extractRoles(String token){
         String rolesString=Jwts.parserBuilder().setSigningKey(secretkey)
                 .build().parseClaimsJws(token).getBody().get("roles",String.class);
         return Set.of(rolesString);
    }

    //Token validation
    public boolean isTokenvalid(String token){
         try{
             Jwts.parserBuilder().setSigningKey(secretkey).build().parseClaimsJws(token);
             return true;
         }catch (JwtException | IllegalArgumentException e){
             return false;
         }

    }

}
