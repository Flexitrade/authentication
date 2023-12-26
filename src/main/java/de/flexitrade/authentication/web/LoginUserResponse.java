package de.flexitrade.authentication.web;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class LoginUserResponse {
	private String accessToken;
	private String type = "Bearer";
	private String refreshToken;
	private Long id;
	private String username;
	private String profileId;
	
	public LoginUserResponse(String accessToken, String refreshToken, Long id, String username, String profileId) {
		this.accessToken = accessToken;
		this.refreshToken = refreshToken;
		this.id = id;
		this.username = username;
		this.profileId = profileId;
	}
}