package com.springauth.entity;

import java.util.HashSet;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.Collection;

@Entity
@Table(name = "app_user")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String password;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "role")
    @Builder.Default
    private Set<String> roles = new HashSet<>();

    @Builder.Default
    @Column(nullable = false)
    private boolean enabled = true;

    // Spring Security doesn't understand plain strings like:
    // It expects every permission or role to be represented as a GrantedAuthority object.
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // to work with each element in the set element by element
        return roles.stream()
                // convert each element into a SimpleGrantedAuthority object
                .map(SimpleGrantedAuthority::new)
                // convert it again to a set
                .collect(Collectors.toSet());
    }

    @Override
    public String getUsername() {
        // We use email as the "username" for login purposes.
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        // Not used in this project; always true.
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        // Could be wired to a "locked" flag (e.g. after N failed logins).
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        // Could be wired to "password must be changed" policies.
        return true;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}
