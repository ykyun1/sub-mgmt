package com.ktds.subs.auth.repository;

import com.ktds.subs.auth.domain.Token;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Long> {
    Optional<Token> findByRefreshToken(String refreshToken);
    void deleteByUserId(String userId);
}
