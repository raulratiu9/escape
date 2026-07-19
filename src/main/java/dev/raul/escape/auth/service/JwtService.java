package dev.raul.escape.auth.service;

import dev.raul.escape.user.AppUser;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
public class JwtService {
    public static final long ACCESS_TOKEN_EXPIRES_IN = 900;

    private final JwtEncoder jwtEncoder;

    public JwtService(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    }

    public String generateAccessToken(AppUser user) {
        Instant now = Instant.now();

        JwsHeader jwsHeader = JwsHeader.with(MacAlgorithm.HS256)
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(
                        jwsHeader,
                        JwtClaimsSet.builder()
                                .issuer("escape-api")
                                .issuedAt(now)
                                .expiresAt(now.plusSeconds(ACCESS_TOKEN_EXPIRES_IN))
                                .subject(user.getId()
                                        .toString())
                                .claim("email", user.getEmail())
                                .claim("role", user.getRole()
                                        .name())
                                .build()
                ))
                .getTokenValue();
    }
}