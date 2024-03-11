package com.security.services;

import com.security.payloads.AuthenticateRequest;
import com.security.payloads.AuthenticationResponse;
import com.security.payloads.RegisterRequest;

public interface AuthenticationService {
    AuthenticationResponse register(RegisterRequest request);

    AuthenticationResponse authenticate(AuthenticateRequest request);
}
