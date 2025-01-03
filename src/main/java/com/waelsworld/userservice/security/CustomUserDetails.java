package com.waelsworld.userservice.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Collection;
import java.util.List;

public class CustomUserDetails implements UserDetails {
    private String username;
    private String password;
    private String role;
    BCryptPasswordEncoder bcryptPasswordEncoder = new BCryptPasswordEncoder();

//    public CustomUserDetails(String username, String password, String role) {
//        this.username = username;
//        this.password = password;
//        this.role = role;
//    }

    @Override
    public String getUsername() {
        return "abcd@gmail.com";
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
    }

    @Override
    public String getPassword() {
        return bcryptPasswordEncoder.encode("password");
    }

    public String getRole() {
        return role;
    }
}
