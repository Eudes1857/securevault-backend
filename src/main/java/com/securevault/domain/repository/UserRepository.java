package com.securevault.domain.repository;

import com.securevault.domain.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import io.lettuce.core.dynamic.annotation.Param;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID>  {

    /**
     * Recherche par hash de l'email (évite de déchiffrer toutes les lignes).
     * [SEC] La recherche ne se fait jamais sur l'email chiffré directement.
     */
    Optional<User> findByEmailHash(String emailHash);

    boolean existsByEmailHash(String emailHash);

    /**
     * Incrémente le compteur d'échecs sans charger l'entité en mémoire.
     */
    @Modifying
    @Query("UPDATE User u SET u.failedAttempts = u.failedAttempts + 1 WHERE u.id = :id")
    void incrementFailedAttempts(@Param("id") UUID id);

    /**
     * Reset du compteur après une connexion réussie.
     */
    @Modifying
    @Query("UPDATE User u SET u.failedAttempts = 0, u.lockedUntil = null WHERE u.id = :id")
    void resetFailedAttempts(@Param("id") UUID id);
}
