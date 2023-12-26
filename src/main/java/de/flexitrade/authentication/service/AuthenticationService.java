package de.flexitrade.authentication.service;

import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import de.flexitrade.authentication.entity.User;
import de.flexitrade.authentication.repository.UserRepository;
import de.flexitrade.authentication.utils.JwtUtils;
import de.flexitrade.authentication.web.ActivateUserRequest;
import de.flexitrade.authentication.web.LoginUserRequest;
import de.flexitrade.authentication.web.LoginUserResponse;
import de.flexitrade.authentication.web.MessageResponse;
import de.flexitrade.authentication.web.RegisterUserRequest;
import de.flexitrade.authentication.web.ResetPasswordRequest;
import de.flexitrade.authentication.web.exception.ApiException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class AuthenticationService {
	private final UserRepository userRepository;
	private final JwtUtils jwtUtils;
	private final PasswordEncoder encoder;

	public ResponseEntity<?> loginUser(@Valid LoginUserRequest loginUserRequest) {
		final var optUser = userRepository.findByUsername(loginUserRequest.getUsername());
		if (optUser.isEmpty()) {
			return new ApiException(HttpStatus.FORBIDDEN, "UNKNOWN_USER").toResponseEntity();
		}
		final User user = optUser.get();
		if (!user.getIsAccountNonLocked()) {
			return new ApiException(HttpStatus.FORBIDDEN, "ACCOUNT_LOCKED").toResponseEntity();
		}
		if (!user.getIsAccountNonExpired()) {
			return new ApiException(HttpStatus.FORBIDDEN, "ACCOUNT_EXPIRED").toResponseEntity();
		}
		if (!user.getIsEnabled()) {
			return new ApiException(HttpStatus.FORBIDDEN, "ACCOUNT_DISABLED").toResponseEntity();
		}
		if (encoder.matches(loginUserRequest.getPassword(), user.getPassword()) == false) {
			return new ApiException(HttpStatus.FORBIDDEN, "WRONG_PASSWORD").toResponseEntity();
		}

		String accessToken = jwtUtils.generate(user.getUsername(), user.getId().toString(),
				user.getProfileId().toString(), JwtUtils.TokenType.ACCESS);
		String refreshToken = jwtUtils.generate(user.getUsername(), user.getId().toString(),
				user.getProfileId().toString(), JwtUtils.TokenType.REFRESH);
		return ResponseEntity.ok(new LoginUserResponse(accessToken, refreshToken, user.getId(), user.getUsername(),
				user.getProfileId()));
	}

	public ResponseEntity<?> registerUser(RegisterUserRequest registerUserRequest) {
		if (userRepository.existsByUsername(registerUserRequest.getUsername())) {
			new ApiException(HttpStatus.BAD_REQUEST, "USERNAME_TAKEN").toResponseEntity();
		}

		if (userRepository.existsByEmail(registerUserRequest.getEmail())) {
			return new ApiException(HttpStatus.BAD_REQUEST, "EMAIL_IN_USE").toResponseEntity();
		}
		// Create new user's account
		try {
			String uniqueId = UUID.randomUUID().toString().replace("-", "");
			String profileId = UUID.randomUUID().toString();
			User user = new User().toBuilder().username(registerUserRequest.getUsername())
					.email(registerUserRequest.getEmail())
					.password(encoder.encode(registerUserRequest.getPassword()))
					.uniqueSecret(uniqueId)
					.profileId(profileId).build();
			userRepository.save(user);
			return ResponseEntity.ok(new MessageResponse("REGISTER_SUCCESS"));
		} catch (Exception e) {
			return new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, e).toResponseEntity();
		}
	}

	public ResponseEntity<?> activateUser(@Valid ActivateUserRequest activateUserRequest) {
		final var optUser = userRepository.findByUsername(activateUserRequest.getUsername());
		if (optUser.isEmpty()) {
			return new ApiException(HttpStatus.BAD_REQUEST, "UNKNOWN_USER").toResponseEntity();
		}
		User user = optUser.get();

		if (user.getUniqueSecret().isBlank() || user.getUniqueSecret().equalsIgnoreCase("none")) {
			return new ApiException(HttpStatus.BAD_REQUEST, "KEY_INVALID").toResponseEntity();
		}

		if (user.getIsAccountNonLocked() == false) {
			return new ApiException(HttpStatus.BAD_REQUEST, "KEY_INVALID").toResponseEntity();
		}

		if (user.getUniqueSecret().equals(activateUserRequest.getSecretkey())) {
			try {
				user.setIsAccountNonLocked(true);
				user.setUniqueSecret("none");
				userRepository.save(user);
				return ResponseEntity.ok(new MessageResponse("ACTIVATE_SUCCESS"));
			} catch (Exception e) {
				return new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage()).toResponseEntity();
			}
		}
		return new ApiException(HttpStatus.BAD_REQUEST, "Activation failed").toResponseEntity();
	}

	public ResponseEntity<?> passwordReset(@Valid ResetPasswordRequest resetPasswordRequest) {
		final var optUser = userRepository.findByUsername(resetPasswordRequest.getUsername());
		if (optUser.isEmpty()) {
			return new ApiException(HttpStatus.BAD_REQUEST, "UNKNOWN_USER").toResponseEntity();
		}
		User user = optUser.get();

		if (user.getUniqueSecret().isBlank() || user.getUniqueSecret().equalsIgnoreCase("none")) {
			return new ApiException(HttpStatus.BAD_REQUEST, "KEY_INVALID").toResponseEntity();
		}

		if (user.getIsAccountNonLocked() == false) {
			return new ApiException(HttpStatus.BAD_REQUEST, "ACCOUNT_LOCKED").toResponseEntity();
		}

		if (user.getIsAccountNonExpired() == false)  {
			return new ApiException(HttpStatus.BAD_REQUEST, "ACCOUNT_EXPIRED").toResponseEntity();
		}
		
		if (user.getIsEnabled() == false) {
			return new ApiException(HttpStatus.BAD_REQUEST, "ACCOUNT_DISABLED").toResponseEntity();
		}
		
		if (user.getUniqueSecret().equals(resetPasswordRequest.getSecretkey())) {
			try {
				user.setUniqueSecret("none");
				user.setPassword(encoder.encode(resetPasswordRequest.getNewPassword()));
				userRepository.save(user);
				return ResponseEntity.ok(new MessageResponse("PWRESET_SUCCESS"));
			} catch (Exception e) {
				return new ApiException(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage()).toResponseEntity();
			}
		}
		return new ApiException(HttpStatus.BAD_REQUEST, "Activation failed").toResponseEntity();
	}
}
