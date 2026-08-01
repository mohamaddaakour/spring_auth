package com.springauth.repository;

import com.springauth.entity.User;
import com.springauth.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByTokenHash(String tokenHash);

    // @Modifying means: this query modifies the database (UPDATE, DELETE, INSERT),
    // not just reads data.
    // we use JPQL query (Java Persistence Query Language) to
    // disable (revoke) all active refresh tokens that belong to this user
    @Modifying
    @Query("UPDATE RefreshToken r SET r.revoked = true WHERE r.user = :user AND r.revoked = false")
    void revokeAllByUser(@Param("user") User user);
}
