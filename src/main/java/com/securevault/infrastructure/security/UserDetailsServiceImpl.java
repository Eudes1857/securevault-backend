package com.securevault.infrastructure.security;


import com.securevault.domain.model.User;
import com.securevault.domain.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Implémentation UserDetailsService pour Spring Security.
 *
 * [SEC] La recherche se fait par email_hash (SHA-256) et non par email chiffré.
 *       Le "username" passé par Spring Security est l'emailHash calculé à
 *       partir de l'email fourni lors du login.
 *
 * [SEC] Le message d'erreur est générique : on ne révèle pas si c'est
 *       l'email ou le mot de passe qui est incorrect.
 *       (DaoAuthenticationProvider.hideUserNotFoundExceptions = true)
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class UserDetailsServiceImpl implements UserDetailsService {
    private final UserRepository userRepository;

    public UserDetails loadUserByUsername (String emailHash) throws UsernameNotFoundException {
        User user = userRepository.findByEmailHash(emailHash)
                .orElse(null);

        if (user == null) {
            log.warn("[SEC] loadUserByUsername: aucun utilisateur trouvé (hash: {}...)", emailHash.length() > 8 ? emailHash.substring(0, 8) : "?");
            throw new UsernameNotFoundException("Identifiants invalides");
        }

        return user;
    }

}
