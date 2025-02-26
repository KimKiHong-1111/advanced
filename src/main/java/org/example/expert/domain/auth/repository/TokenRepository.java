package org.example.expert.domain.auth.repository;

import org.example.expert.domain.auth.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TokenRepository extends JpaRepository<RefreshToken, Long> {
    RefreshToken findByRefreshToken(String accessToken);
}
