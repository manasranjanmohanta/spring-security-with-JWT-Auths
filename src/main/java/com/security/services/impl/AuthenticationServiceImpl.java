package com.security.services.impl;

import com.security.config.JwtService;
import com.security.enitites.Role;
import com.security.enitites.User;
import com.security.payloads.AuthenticateRequest;
import com.security.payloads.AuthenticationResponse;
import com.security.payloads.RegisterRequest;
import com.security.repositories.UserRepository;
import com.security.services.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final JwtService jwtService;

    private AuthenticationManager authenticationManager;

    @Override
    public AuthenticationResponse register(RegisterRequest request) {
        // building user entity objec using builder design pattern
        var user = User.builder()
                .firsName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.ADMIN)
                .build();

        // saving into the db
        userRepository.save(user);

        // generating token
        String jwtToken = jwtService.generateToken(user);

        // building AuthenticationResponse object

//        AuthenticationResponse response = new AuthenticationResponse();
//        response.setToken(token);

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    @Override
    public AuthenticationResponse authenticate(AuthenticateRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        // searching in the db for current user
        User user = userRepository.findByEmail(request.getEmail()).orElseThrow(() -> new UsernameNotFoundException("User is not found with email: " + request.getEmail()));

        // if found then
        // generating token
        String jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
}
