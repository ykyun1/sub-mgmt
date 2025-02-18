package com.ktds.subs.auth.repository;

import com.ktds.subs.auth.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, String> {
    Optional<User> findByProviderAndProviderUserId(String provider, String providerUserId);
}
