package com.securevault.domain.model;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

/**
 * Entité utilisateur.
 *
 * [SEC] L'email est chiffré en base (email) ; le champ email_hash (SHA-256 déterministe)
 * permet la recherche sans déchiffrer toutes les lignes.
 *
 * Implémente UserDetails pour l'intégration Spring Security.
 */
@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /** Email chiffré (AES-GCM). Valeur lisible uniquement après déchiffrement. */
    @Column(name = "email", nullable = false, unique = true)
    private String email;

    /** Hash SHA-256 de l'email en minuscules pour les recherches rapides. */
    @Column(name = "email_hash", nullable = false, unique = true, length = 64)
    private String emailHash;

    /** Hash bcrypt — coût 12 minimum. */
    @Column(name = "password_hash", nullable = false, unique = true, length = 60)
    private String passwordHash;

    /** Secret TOTP chiffré en AES-GCM. Null si MFA non activé. */
    @Column(name = "mfa_secret")
    private String mfaSecret;

    @Column(name = "mfa_enabled", nullable = false)
    @Builder.Default
    private boolean mfaEnabled = false;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)

    private Role role;

    /** Compteur de tentatives échouées (reset à 0 après succès). */
    @Column(name = "failed_attempts", nullable = false)
    @Builder.Default
    private int failedAttempts = 0;

    /** Si non null et dans le futur, le compte est verrouillé. */
    @Column(name = "locked_until")
    private Instant lockedUntil;

    @Column(nullable = false)
    @Builder.Default
    private boolean active = true;

    @Column(name = "created_at", nullable = false, updatable = false)
    @Builder.Default
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    @Builder.Default
    private Instant updatedAt  = Instant.now();

    // ── UserDetails ──────────────────────────────────────────────────────────
    //@Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
    }

    //@Override
    public String getPassword() {
        return this.passwordHash;
    }

    //@Override
    public String getUsername() {
        return email;
    }

    public boolean isAccountNonExpired() {
        return  true;
    }

    public boolean isAccountNonLocked() {
        return lockedUntil == null || lockedUntil.isBefore(Instant.now());
    }

    public boolean isCredentialsNonExpired() {
        return true;
    }

    public boolean isEnabled() {
        return active;
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    public boolean isLocked() {
        return lockedUntil != null && lockedUntil.isAfter(Instant.now());
    }

    public void incrementFailedAttempts() {
        this.failedAttempts++;
    }

    public void resetFailedAttempts() {
        this.failedAttempts = 0;
        this.lockedUntil = null;
    }
}
