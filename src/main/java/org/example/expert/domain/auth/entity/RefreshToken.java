package org.example.expert.domain.auth.entity;

import jakarta.persistence.*;
import lombok.Getter;

import java.time.LocalDateTime;
import java.util.Arrays;

@Getter
@Entity
@Table(name = "refreshTokens")
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String token;
    private LocalDateTime createdAt;
    private String refreshToken;

    public RefreshToken(Long id, byte[] token) {
        this.id = id;
        this.token = Arrays.toString(token);
    }

    public RefreshToken() {

    }
}
