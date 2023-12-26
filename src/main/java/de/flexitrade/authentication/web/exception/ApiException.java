package de.flexitrade.authentication.web.exception;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import com.fasterxml.jackson.annotation.JsonFormat;

import lombok.Data;

@Data
public class ApiException {
	private HttpStatus status;
	@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "dd-MM-yyyy hh:mm:ss")
	private LocalDateTime timestamp;
	private String cause;
	private String message;
	private List<ApiExceptionDetail> details;

	private ApiException() {
		timestamp = LocalDateTime.now();
	}

	public ApiException(HttpStatus status) {
		this();
		this.status = status;
	}

	public ApiException(HttpStatus status, Throwable ex) {
		this();
		this.status = status;
		this.cause = "Unexpected error";
		this.message = ex.getLocalizedMessage();
	}

	public ApiException(HttpStatus status, String cause) {
		this();
		this.status = status;
		this.cause = cause;
	}

	public ApiException(HttpStatus status, String cause, Throwable ex) {
		this();
		this.status = status;
		this.cause = cause;
		this.message = ex.getLocalizedMessage();
	}
	
	public void addExceptionDetail(ApiExceptionDetail detail) {
        if (details == null) {
        	details = new ArrayList<>();
        }
        details.add(detail);
    }
	
	public void addValidationError(String object, String field, Object rejectedValue, String message) {
		addExceptionDetail(new ApiValidationException(object, field, rejectedValue, message));
    }

    public void addValidationError(String object, String message) {
    	addExceptionDetail(new ApiValidationException(object, message));
    }
    
    public ResponseEntity<Object> toResponseEntity() {
    	return new ResponseEntity<>(this, this.getStatus());
    }
}
