package de.flexitrade.authentication.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import de.flexitrade.authentication.service.AuthenticationService;
import de.flexitrade.authentication.web.ActivateUserRequest;
import de.flexitrade.authentication.web.LoginUserRequest;
import de.flexitrade.authentication.web.RegisterUserRequest;
import de.flexitrade.authentication.web.ResetPasswordRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class AuthenticationController {
	private final AuthenticationService registerService;

	@PostMapping(value = "login")
	public ResponseEntity<?> login(@Valid @RequestBody LoginUserRequest loginRequest) {
		return registerService.loginUser(loginRequest);
	}
	
	@PostMapping(value = "register")
	public ResponseEntity<?> register(@Valid @RequestBody RegisterUserRequest registerUserRequest) {
		return registerService.registerUser(registerUserRequest);
	}
	
	@PostMapping(value = "activate")
	public ResponseEntity<?> activate(@Valid @RequestBody ActivateUserRequest activateUserRequest) {
		return registerService.activateUser(activateUserRequest);
	}
	
	@PostMapping(value = "pwreset")
	public ResponseEntity<?> passwordReset(@Valid @RequestBody ResetPasswordRequest resetPasswordRequest) {
		return registerService.passwordReset(resetPasswordRequest);
	}
}